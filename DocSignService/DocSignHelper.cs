using DocSignService.Models;
using iTextSharp.text.pdf.security;
using Newtonsoft.Json;
using System;
using System.Configuration;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Script.Serialization;
using static DocSignService.Models.ExternalSignature;

namespace DocSignService
{
  public class DocSignHelper
  {
    private static object fFileLock = new object();

    public static void Log(string message, LogLevelEnum logLevel, string authenticationToken)
    {
      var logPath = AppSettingsCache.GetAppSetting("LogLocation");
      if (String.IsNullOrEmpty(logPath))
        return;
      LogLevelEnum logLevelSettings;
      if (!Enum.TryParse(AppSettingsCache.GetAppSetting("LogLevel"), out logLevelSettings))
        logLevelSettings = LogLevelEnum.Error;
      if (logLevel <= logLevelSettings)
      {
        var logLine = string.Format(
          "{0}\t{1}\t{2}\t{3}{4}",
          DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss"),
          authenticationToken,
          logLevel.ToString(),
          message,
          Environment.NewLine);
        
        lock (fFileLock)
        {
          File.AppendAllText(logPath, logLine);
        }
      }
    }
    public static bool IsEccPublicKey(X509Certificate2 certificate)
    {
      if (certificate.PublicKey.Oid.FriendlyName == "ECC")
        return true;
      else
        return false;
    }

    public static string Base64Encode(string plainText)
    {
      if (plainText == null)
        return null;
      var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
      return System.Convert.ToBase64String(plainTextBytes);
    }

    public static string Base64Decode(string base64EncodedData)
    {
      if (base64EncodedData == null)
        return null;
      var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
      return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
    }

    public static string SerializeItemJSON(object item)
    {
      JavaScriptSerializer jss = new JavaScriptSerializer();
      jss.MaxJsonLength = Int32.MaxValue;
      return jss.Serialize(item);
    }

    public static object DeserializeItemJSON(string inputString, Type type)
    {
      var plainTextBytes = Encoding.UTF8.GetBytes(inputString);
      var base64String = Convert.ToBase64String(plainTextBytes);
      byte[] buffer = Convert.FromBase64String(base64String);
      string s = Encoding.UTF8.GetString(buffer);
      JavaScriptSerializer js = new JavaScriptSerializer
      {
        MaxJsonLength = Int32.MaxValue  // Set to the maximum possible length
      };

      return js.Deserialize(s, type);
    }

    private static HttpClient InitClient(string authenticationToken)
    {
      HttpClient client = new HttpClient();
      client.BaseAddress = new Uri(AppSettingsCache.GetAppSetting("ClientApiURL"));
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
      client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authenticationToken);
      return client;
    }

    public static bool CacheTokenWithData(string fUserProfile, string fAuthenticationToken, HashModel hashes)
    {
      using (var client = InitClient(fAuthenticationToken))
      {
        string updateTokenUrl = AppSettingsCache.GetAppSetting("ClientApiURL") + "signatures/setHashSignature/" + fAuthenticationToken;
        var responseUpdate = client.PutAsJsonAsync<HashModel>(updateTokenUrl, hashes).Result;
        if (responseUpdate.IsSuccessStatusCode)
        {
          return true;
        }
        else
        {
          Log($"CacheTokenWithData unsuccessful- statusCode={responseUpdate.StatusCode};", LogLevelEnum.Error, fAuthenticationToken);
          return false;
        }
      }
    }

    public static HashModel GetCachedTokenData(string fAuthenticationToken)
    {
      using (var client = InitClient(fAuthenticationToken))
      {
        string updateTokenUrl = AppSettingsCache.GetAppSetting("ClientApiURL") + "signatures/" + fAuthenticationToken;
        var responseGet = client.GetAsync(updateTokenUrl).Result;
        if (responseGet.IsSuccessStatusCode)
        {
          var responseString = responseGet.Content.ReadAsStringAsync().Result;
          return JsonConvert.DeserializeObject<HashModel>(responseString);
        }
        else
        {
          Log($"CacheTokenWithData unsuccessful- statusCode={responseGet.StatusCode};", LogLevelEnum.Error, fAuthenticationToken);
          return null;
        }
      }
    }

    public static string GetHashDigest(string content, string hashAlgorithm)
    {
      if (hashAlgorithm == null)
      {
        return content;
      }

      var contentBin = Convert.FromBase64String(content);
      var digest = GetHashDigest(contentBin, hashAlgorithm);
      return Convert.ToBase64String(digest);
    }

    public static byte[] GetHashDigest(byte[] content, string hashAlgorithm)
    {
      if (hashAlgorithm == null)
      {
        return content;
      }

      switch (hashAlgorithm)
      {
        case "SHA1":
          {
            return SHA1Managed.Create().ComputeHash(content);
          }
        case "SHA256":
          {
            return SHA256Managed.Create().ComputeHash(content);
          }
        case "SHA384":
          {
            return SHA384Managed.Create().ComputeHash(content);
          }
        case "SHA512":
          {
            return SHA512Managed.Create().ComputeHash(content);
          }
        default:
          {
            throw new NotSupportedException("Unsupported hash algorithm " + hashAlgorithm);
          }
      }
    }

    public static PdfPKCS7Dto GetPdfPKCS7Dto(string signatureName, PdfPKCS7 pk)
    {
      var result = new PdfPKCS7Dto();
      result.IsValidSignature = pk.Verify();
      result.SigningCertificate = pk.SigningCertificate.GetEncoded();
      result.SignatureName = signatureName;
      result.VerifiedSignature = true;
      result.TimeStampDate = pk.TimeStampDate;
      if (pk.TimeStampToken != null) 
      {
        result.TimeStampTokenEncoded = pk.TimeStampToken.GetEncoded();
        var tst = new TimeStampTokenDto();
        tst.IsValidSignature = pk.VerifyTimestampImprint();
        if (pk.TimeStampToken.TimeStampInfo.TstInfo.Nonce != null)
          tst.Nonce = pk.TimeStampToken.TimeStampInfo.TstInfo.Nonce.GetEncoded();
        tst.SignDate = pk.TimeStampDate;
        tst.Micros = pk.TimeStampToken.TimeStampInfo.GenTimeAccuracy == null ? 0 : pk.TimeStampToken.TimeStampInfo.GenTimeAccuracy.Micros;
        tst.Millis = pk.TimeStampToken.TimeStampInfo.GenTimeAccuracy == null ? 0 : pk.TimeStampToken.TimeStampInfo.GenTimeAccuracy.Millis;
        tst.Seconds = pk.TimeStampToken.TimeStampInfo.GenTimeAccuracy == null ? 0 : pk.TimeStampToken.TimeStampInfo.GenTimeAccuracy.Seconds;
        tst.GeneralizedTime = pk.TimeStampToken.TimeStampInfo.TstInfo.GenTime.ToDateTime();
        tst.Version = pk.TimeStampToken.ToCmsSignedData().Version.ToString();
        tst.Ordering = pk.TimeStampToken.TimeStampInfo.TstInfo.Ordering.IsTrue;
        tst.PolicyId = pk.TimeStampToken.TimeStampInfo.TstInfo.Policy.ToString();

        result.TimeStampToken = tst;
      }
      result.SignDate = pk.SignDate;
      if (pk.SigningCertificate != null)
      {
        result.SigningCertificate = pk.SigningCertificate.GetEncoded();
      }
      result.SignName = pk.SignName;
      return result;
    }
  }
}
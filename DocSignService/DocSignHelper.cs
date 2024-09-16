using Newtonsoft.Json;
using System;
using System.Configuration;
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
      JavaScriptSerializer js = new JavaScriptSerializer();

      return js.Deserialize(s, type);
    }

    private static HttpClient InitClient(string authenticationToken)
    {
      HttpClient client = new HttpClient();
      client.BaseAddress = new Uri(ConfigurationManager.AppSettings["ClientApiURL"]);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
      client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authenticationToken);
      return client;
    }

    public static bool CacheTokenWithData(string fUserProfile, string fAuthenticationToken, HashModel hashes)
    {
      using (var client = InitClient(fAuthenticationToken))
      {
        string updateTokenUrl = ConfigurationManager.AppSettings["ClientApiURL"] + "signatures/setHashSignature/" + fAuthenticationToken;
        var responseUpdate = client.PutAsJsonAsync<HashModel>(updateTokenUrl, hashes).Result;
        if (responseUpdate.IsSuccessStatusCode)
        {
          return true;
        }
        else
        {
          return false;
        }
      }
    }

    public static HashModel GetCachedTokenData(string fAuthenticationToken)
    {
      using (var client = InitClient(fAuthenticationToken))
      {
        string updateTokenUrl = ConfigurationManager.AppSettings["ClientApiURL"] + "signatures/" + fAuthenticationToken;
        var responseGet = client.GetAsync(updateTokenUrl).Result;
        if (responseGet.IsSuccessStatusCode)
        {
          var responseString = responseGet.Content.ReadAsStringAsync().Result;
          return JsonConvert.DeserializeObject<HashModel>(responseString);
        }
        else
        {
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
  }
}
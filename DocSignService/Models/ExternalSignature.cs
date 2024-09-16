using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace DocSignService.Models
{
  public class ExternalSignature : IExternalSignature
  {
    private X509Certificate2 fCertificate;
    private string fHashAlgorithm;
    private byte[] fSignature;
    private byte[] fSignatureMessage;
    private string fAuthenticationToken;
    private bool fIsExternalSigning;
    private string fUserSID;

    public class HashModel
    {
      public byte[] Hash { get; set; }
      public byte[] SignedHash { get; set; }
      public bool IsFinished { get; set; }
    }

    public ExternalSignature(
      X509Certificate2 certificate,
      string hashAlgorithm,
      PdfSignatureAppearance sap,
      string authenticationToken,
      bool isExternalSigning)
    {
      if (certificate == null)
      {
        throw new ArgumentNullException("certificate");
      }

      if (string.IsNullOrWhiteSpace(hashAlgorithm))
      {
        throw new ArgumentNullException("hashAgorithm");
      }

      if (sap == null)
      {
        throw new ArgumentNullException("sap");
      }

      fCertificate = certificate;
      fHashAlgorithm = hashAlgorithm;
      fAuthenticationToken = authenticationToken;
      fIsExternalSigning = isExternalSigning;
    }

    public string GetEncryptionAlgorithm()
    {
      if (DocSignHelper.IsEccPublicKey(fCertificate))
        return $"ECDSA_{fHashAlgorithm}";
      else
        return "RSA";
    }

    public string GetHashAlgorithm()
    {
      return fHashAlgorithm;
    }

    public byte[] Sign(byte[] message)
    {
      fSignatureMessage = message;
      if (fIsExternalSigning || !DocSignHelper.IsEccPublicKey(fCertificate))
      {
        FillDummySignature();
        return fSignature;
      }

      if (fCertificate != null && fCertificate.HasPrivateKey)
      {
        var rsaCng = RSACertificateExtensions.GetRSAPrivateKey(fCertificate) as RSACng;
        if (rsaCng != null)
        {
          var hashAlgorithmName = new HashAlgorithmName(fHashAlgorithm);
          var signature = rsaCng.SignHash(Hash, hashAlgorithmName, RSASignaturePadding.Pkcs1);
          fSignature = signature;
          return signature;
        }
      }
      else
      {
        HashModel hashesSend = new HashModel();
        hashesSend.Hash = Hash;
        var serializedHash = DocSignHelper.Base64Encode(DocSignHelper.SerializeItemJSON(hashesSend));
        DocSignHelper.CacheTokenWithData(fUserSID, fAuthenticationToken, hashesSend);

        byte[] signedHash = null;
        while (signedHash == null)
        {
          HashModel hashesReceive = DocSignHelper.GetCachedTokenData(fAuthenticationToken);
          if (hashesReceive.IsFinished)
            break;
          if ((hashesReceive != null) && (hashesReceive.SignedHash != null))
          {
            fSignature = hashesReceive.SignedHash;
            signedHash = hashesReceive.SignedHash;
            if (DocSignHelper.IsEccPublicKey(fCertificate))
              signedHash = ConstructEcdsaSigValue(hashesReceive.SignedHash);
            DocSignHelper.CacheTokenWithData(fUserSID, fAuthenticationToken, null);
            break;
          }
          Thread.Sleep(500);
        }
        return signedHash;
      }
      return null;
    }

    public byte[] Signature
    {
      get
      {
        if (fSignature == null)
        {
          throw new ApplicationException("Call siganature after sign operation.");
        }

        return fSignature;
      }
    }

    public byte[] Hash
    {
      get
      {
        if (fSignatureMessage == null)
        {
          throw new ApplicationException("Signature message is null.");
        }

        return DocSignHelper.GetHashDigest(fSignatureMessage, GetHashAlgorithm());
      }
    }

    public byte[] SignatureMessage
    {
      get
      {
        if (fSignatureMessage == null)
        {
          throw new ApplicationException("Call siganaturemessage after sign operation.");
        }

        return fSignatureMessage;
      }
    }

    private void FillDummySignature()
    {
      var signatureLength = GetSignatureLength();
      fSignature = new byte[signatureLength];

      for (int i = 0; i < signatureLength; i++)
      {
        if (i % 10 == 0)
          fSignature[i] = 0x21;
        else
          fSignature[i] = 0x20;
      }
    }

    private int GetSignatureLength()
    {
      if (fCertificate.PublicKey.Key.KeySize == 1024)
        return 128;
      if (fCertificate.PublicKey.Key.KeySize == 2048)
        return 256;
      throw new Exception("Unsuporrted certificate key length");
    }

    public static byte[] ReplaceSignatureInPdf(byte[] src, byte[] replace, byte[] replaceWith)
    {
      string hex = BitConverter.ToString(src);
      hex = hex.Replace("-", "");

      byte[] replaceByteArray = TextSharpConvertToHex(replace);
      string replaceString = BitConverter.ToString(replaceByteArray);
      replaceString = replaceString.Replace("-", "");

      byte[] replaceWithByteArray = TextSharpConvertToHex(replaceWith);
      string replaceWithString = BitConverter.ToString(replaceWithByteArray);
      replaceWithString = replaceWithString.Replace("-", "");

      if (!hex.Contains(replaceString))
      {
        throw new Exception("Wrong signature.");
      }

      hex = hex.Replace(replaceString, replaceWithString);
      int numberChars = hex.Length;
      var bytes = new byte[numberChars / 2];
      for (int i = 0; i < numberChars; i += 2)
        bytes[i / 2] = System.Convert.ToByte(hex.Substring(i, 2), 16);
      return bytes;
    }

    private static byte[] TextSharpConvertToHex(byte[] content)
    {
      var buf = new ByteBuffer();
      int len = content.Length;
      for (int k = 0; k < len; ++k)
        buf.AppendHex(content[k]);

      return buf.ToByteArray();
    }

    private static byte[] ConstructEcdsaSigValue(byte[] rs)
    {
      if (rs.Length < 2 || rs.Length % 2 != 0)
        throw new Exception("Invalid length");

      int halfLen = rs.Length / 2;

      byte[] half1 = new byte[halfLen];
      Array.Copy(rs, 0, half1, 0, halfLen);
      var r = new Org.BouncyCastle.Math.BigInteger(1, half1);

      byte[] half2 = new byte[halfLen];
      Array.Copy(rs, halfLen, half2, 0, halfLen);
      var s = new Org.BouncyCastle.Math.BigInteger(1, half2);

      var derSequence = new Org.BouncyCastle.Asn1.DerSequence(
          new Org.BouncyCastle.Asn1.DerInteger(r),
          new Org.BouncyCastle.Asn1.DerInteger(s));

      return derSequence.GetDerEncoded();
    }
  }
}
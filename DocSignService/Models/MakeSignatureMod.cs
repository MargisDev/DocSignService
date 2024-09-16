using iTextSharp.text.log;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;

namespace DocSignService.Models
{
  public static class MakeSignatureMod
  {
    private static readonly ILogger LOGGER = LoggerFactory.GetLogger(typeof(MakeSignatureMod));

    public static void SignDetached(PdfSignatureAppearance sap, IExternalSignature externalSignature, ICollection<X509Certificate> chain, ICollection<ICrlClient> crlList, IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize, CryptoStandard sigtype)
    {
      List<X509Certificate> list = new List<X509Certificate>(chain);
      ICollection<byte[]> collection = null;
      int num = 0;
      while (collection == null && num < list.Count)
      {
        collection = ProcessCrl(list[num++], crlList);
      }

      if (estimatedSize == 0)
      {
        estimatedSize = 8192;
        if (collection != null)
        {
          foreach (byte[] item in collection)
          {
            estimatedSize += item.Length + 10;
          }
        }

        if (ocspClient != null)
        {
          estimatedSize += 4192;
        }

        if (tsaClient != null)
        {
          estimatedSize += 4192;
        }
      }

      sap.Certificate = list[0];
      if (sigtype == CryptoStandard.CADES)
      {
        sap.AddDeveloperExtension(PdfDeveloperExtension.ESIC_1_7_EXTENSIONLEVEL2);
      }

      PdfSignature pdfSignature = new PdfSignature(PdfName.ADOBE_PPKLITE, (sigtype == CryptoStandard.CADES) ? PdfName.ETSI_CADES_DETACHED : PdfName.ADBE_PKCS7_DETACHED);
      pdfSignature.Reason = sap.Reason;
      pdfSignature.Location = sap.Location;
      pdfSignature.SignatureCreator = sap.SignatureCreator;
      pdfSignature.Contact = sap.Contact;
      pdfSignature.Date = new PdfDate(sap.SignDate);
      sap.CryptoDictionary = pdfSignature;
      Dictionary<PdfName, int> dictionary = new Dictionary<PdfName, int>();
      dictionary[PdfName.CONTENTS] = estimatedSize * 2 + 2;
      sap.PreClose(dictionary);
      string hashAlgorithm = externalSignature.GetHashAlgorithm();
      PdfPKCS7Mod pdfPKCS = new PdfPKCS7Mod(null, chain, hashAlgorithm, hasRSAdata: false);
      DigestUtilities.GetDigest(hashAlgorithm);
      Stream rangeStream = sap.GetRangeStream();
      byte[] secondDigest = DigestAlgorithms.Digest(rangeStream, hashAlgorithm);
      byte[] ocsp = null;
      if (chain.Count >= 2 && ocspClient != null)
      {
        ocsp = ocspClient.GetEncoded(list[0], list[1], null);
      }

      byte[] authenticatedAttributeBytes = pdfPKCS.getAuthenticatedAttributeBytes(secondDigest, ocsp, collection, sigtype);
      byte[] digest = externalSignature.Sign(authenticatedAttributeBytes);
      pdfPKCS.SetExternalDigest(digest, null, externalSignature.GetEncryptionAlgorithm());
      byte[] encodedPKCS = pdfPKCS.GetEncodedPKCS7(secondDigest, tsaClient, ocsp, collection, sigtype);
      if (estimatedSize < encodedPKCS.Length)
      {
        throw new IOException("Not enough space");
      }

      byte[] array = new byte[estimatedSize];
      Array.Copy(encodedPKCS, 0, array, 0, encodedPKCS.Length);
      PdfDictionary pdfDictionary = new PdfDictionary();
      pdfDictionary.Put(PdfName.CONTENTS, new PdfString(array).SetHexWriting(hexWriting: true));
      sap.Close(pdfDictionary);
    }

    public static ICollection<byte[]> ProcessCrl(X509Certificate cert, ICollection<ICrlClient> crlList)
    {
      if (crlList == null)
      {
        return null;
      }

      List<byte[]> list = new List<byte[]>();
      foreach (ICrlClient crl in crlList)
      {
        if (crl != null)
        {
          ICollection<byte[]> encoded = crl.GetEncoded(cert, null);
          if (encoded != null)
          {
            LOGGER.Info("Processing " + crl.GetType().Name);
            list.AddRange(encoded);
          }
        }
      }

      if (list.Count == 0)
      {
        return null;
      }

      return list;
    }
  }
}
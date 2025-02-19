using DocSignService.Models;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using iTextSharp.tool.xml.html.head;
using Org.BouncyCastle.Asn1.Ocsp;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace DocSignService
{
  public class SignDocProc
  {
    public static async Task<DocSignResponse> SignPdfDoc(DocSignRequest input)
    {
      DocSignResponse result = new DocSignResponse();
      try
      {
        if (input == null)
        {
          DocSignHelper.Log($"Request is null", LogLevelEnum.Error, null);
          return result;
        }

        DocSignHelper.Log($"request deserialized.", LogLevelEnum.Debug, input.AuthenticationToken);
        var msSignedPdfWithMissingPkcs7Signature = new MemoryStream();
        if (input.PdfToSign == null || input.PdfToSign.Length == 0)
        {
          DocSignHelper.Log($"PdfToSign is null or length = 0", LogLevelEnum.Error, input.AuthenticationToken);
          return result;
        }
        var reader = new PdfReader(input.PdfToSign);
        var acroFields = reader.AcroFields;
        int signatureCount = acroFields.GetSignatureNames().Count;
        var stp = signatureCount > 0 ?
          PdfStamper.CreateSignature(reader, msSignedPdfWithMissingPkcs7Signature, '\0', null, true) :
          PdfStamper.CreateSignature(reader, msSignedPdfWithMissingPkcs7Signature, '\0');

        var sap = stp.SignatureAppearance;
        sap.Acro6Layers = true;
        if (input.Sap.PageRect != null)
        {
          DocSignHelper.Log($"VisibleSignature: " +
            $"Left={input.Sap.PageRect.Left}," +
            $"Bottom={input.Sap.PageRect.Bottom}," +
            $"Right={input.Sap.PageRect.Right}," +
            $"Top={input.Sap.PageRect.Top}," +
            $"Page={input.Sap.Page}," +
            $"FieldName={input.Sap.FieldName}",
            LogLevelEnum.Debug,
            input.AuthenticationToken);
          Rectangle rect = new Rectangle(input.Sap.PageRect.Left, input.Sap.PageRect.Bottom, input.Sap.PageRect.Right, input.Sap.PageRect.Top);
          sap.SetVisibleSignature(rect, input.Sap.Page, input.Sap.FieldName);
        }
        else
        {
          DocSignHelper.Log($"No Signature visualization",
            LogLevelEnum.Debug,
            input.AuthenticationToken);
          Rectangle rect = new Rectangle(0,0,0,0);
          sap.SetVisibleSignature(rect, input.Sap.Page, input.Sap.FieldName);
        }
        
        sap.CryptoDictionary = input.Sap.CryptoDictionary;
        sap.CertificationLevel = PdfSignatureAppearance.NOT_CERTIFIED;
        var template = sap.GetLayer(2);

        foreach (SignatureElementDTO item in input.Sap.Elements)
        {
          var ctItem = new ColumnText(template) { RunDirection = 0 };
          ctItem.SetSimpleColumn(
            item.Position.X,
            item.Position.Y,
            item.Position.Width,
            item.Position.Height,
            item.Position.Leading,
            item.Position.Alignment
          );
          if (item.Pdf != null)
          {
            using (var pdfStream = new MemoryStream(item.Pdf))
            {
              var pdfReader = new PdfReader(pdfStream);
              PdfImportedPage importedPage = stp.GetImportedPage(pdfReader, 1); // assuming first page, adjust if necessary
              Image pdfImage = Image.GetInstance(importedPage);
              pdfImage.ScaleToFit(item.Position.Width, item.Position.Height);
              pdfImage.SetAbsolutePosition(item.Position.X, item.Position.Y);
              template.AddImage(pdfImage);
            }
            DocSignHelper.Log($"item.Pdf added", LogLevelEnum.Debug, input.AuthenticationToken);
          }
          else if (item.Image != null)
          {
            ctItem.AddElement(Image.GetInstance(item.Image));
            DocSignHelper.Log($"item.Image added", LogLevelEnum.Debug, input.AuthenticationToken);
          }
          else if (item.ChunkList != null)
          {
            var pSignatureText = new Paragraph();
            pSignatureText.SetLeading(1.0f, 1.0f);
            foreach (ChunkDTO chunk in item.ChunkList)
              pSignatureText.Add(new Chunk(chunk.Content, GetFont(chunk.Font.FontFilename, chunk.Font.Size)));
            ctItem.AddElement(pSignatureText);
            DocSignHelper.Log($"item.ChunkList added", LogLevelEnum.Debug, input.AuthenticationToken);
          }
          ctItem.Go();
        }
        var cp = new Org.BouncyCastle.X509.X509CertificateParser();
        var pdfCertificate = cp.ReadCertificate(input.PdfCertificate);
        var chain = new[] { pdfCertificate };
        DocSignHelper.Log($"certificate read", LogLevelEnum.Debug, input.AuthenticationToken);

        var signerCertificate = new X509Certificate2(input.SignerCertificate);
        var es = new ExternalSignature(signerCertificate, input.HashAlgorithm ?? "SHA1", sap, input.AuthenticationToken, input.IsExternalSigning);

        DocSignHelper.Log($"before SignDetached", LogLevelEnum.Debug, input.AuthenticationToken);
        MakeSignatureMod.SignDetached(sap, es, chain, null, null, null, 0, CryptoStandard.CMS);
        var signatureLength = es.Signature == null ? 0 : es.Signature.Length;
        var signatureMessageLength = es.SignatureMessage == null ? 0 : es.SignatureMessage.Length;
        DocSignHelper.Log($"after SignDetached: SignatureLength={signatureLength}, SignatureMessageLength={signatureMessageLength}", LogLevelEnum.Debug, input.AuthenticationToken);

        result.PdfFakeSignedValue = Convert.ToBase64String(es.Signature);
        result.PdfHashToSignBase64 = Convert.ToBase64String(es.SignatureMessage);
        result.SignedPdfWithMissingSignatureB64 = Convert.ToBase64String(msSignedPdfWithMissingPkcs7Signature.GetBuffer());
      }
      catch(Exception ex)
      {
        DocSignHelper.Log($"ERROR! errorMessge={ex.Message}", LogLevelEnum.Error, input.AuthenticationToken);
      }
      return result;
    }

    private static Font GetFont(string fontFilename, int fontSize)
    {
      var ft = BaseFont.CreateFont(fontFilename, BaseFont.IDENTITY_H, BaseFont.EMBEDDED, true);
      var ftDefault = new Font(ft, fontSize);
      return ftDefault;
    }
  }
}
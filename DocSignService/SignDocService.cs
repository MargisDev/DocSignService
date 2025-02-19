using DocSignService.Models;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using System;
using System.Collections.Generic;

namespace DocSignService
{
  public class SignDocService : ISignDocService
  {
    public DocSignResponse SignDoc(string input)
    {
      DocSignHelper.Log("signing started", LogLevelEnum.Debug, null);
      DocSignRequest request;
      try
      {
        request = DocSignHelper.DeserializeItemJSON(input, typeof(DocSignRequest)) as DocSignRequest;
      }
      catch (Exception e)
      {
        DocSignHelper.Log("deserialization error: ", LogLevelEnum.Error, e.Message);
        return new DocSignResponse();
      }
      var result = SignDocProc.SignPdfDoc(request).Result;
      DocSignHelper.Log("signing finished", LogLevelEnum.Debug, request.AuthenticationToken);
      return result;
    }

    public VerifySignatureResponse VerifySignature(string input)
    {
      var result = new VerifySignatureResponse();
      DocSignHelper.Log("verifySignature started", LogLevelEnum.Debug, null);
      VerifySignatureRequest request;
      try
      {
        request = DocSignHelper.DeserializeItemJSON(input, typeof(VerifySignatureRequest)) as VerifySignatureRequest;
      }
      catch (Exception e)
      {
        DocSignHelper.Log("deserialization verifySignature error: ", LogLevelEnum.Error, e.Message);
        result.ErrorMessage = e.Message;
        return result;
      }

      PdfReader reader = new PdfReader(request.PdfDocument);
      AcroFields af = reader.AcroFields;
      var names = af.GetSignatureNames();
      var signatureList = new List<PdfPKCS7Dto>();
      foreach(string name in names)
      {
        try
        {
          PdfPKCS7 pk = af.VerifySignature(name as string);
          signatureList.Add(DocSignHelper.GetPdfPKCS7Dto(name, pk));
        }
        catch (Exception e) {
          DocSignHelper.Log($"Error Verifying signature '{name}'", LogLevelEnum.Error, e.Message);
        }
      }
      result.SignatureList = signatureList;
      return result;
    }
  }
}
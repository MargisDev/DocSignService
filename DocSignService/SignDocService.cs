using DocSignService.Models;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using System;
using System.Collections.Generic;
using System.Reflection;

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
      DocSignHelper.Log($"request deserialized.", LogLevelEnum.Debug, request.AuthenticationToken);
      var result = SignDocProc.SignPdfDoc(request).Result;
      DocSignHelper.Log("signing finished", LogLevelEnum.Debug, request.AuthenticationToken);
      return result;
    }

    public VerifySignatureResponse VerifySignature(string input)
    {
      var result = new VerifySignatureResponse();
      List<string> names = new List<string>();
      AcroFields af;
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
        result.ErrorEnum = (int)ErrorEnum.DeserializationError;
        return result;
      }
      try
      {
        PdfReader reader = new PdfReader(request.PdfDocument);
        af = reader.AcroFields;
        names = af.GetSignatureNames();
      }
      catch (Exception e)
      {
        DocSignHelper.Log("Error opening PDF: ", LogLevelEnum.Error, e.Message);
        result.ErrorMessage = e.Message;
        result.ErrorEnum = (int)ErrorEnum.ErrorOpeningPdf;
        return result;
      }
      var signatureList = new List<PdfPKCS7Dto>();
      foreach(string name in names)
      {
        try
        {
          PdfPKCS7 pk = af.VerifySignature(name as string);
          signatureList.Add(DocSignHelper.GetPdfPKCS7Dto(name, pk));
        }
        catch (Exception e) {
          signatureList.Add(new PdfPKCS7Dto() { SignatureName = name });
          DocSignHelper.Log($"Error Verifying signature '{name}'", LogLevelEnum.Error, e.Message);
        }
      }
      result.SignatureList = signatureList;
      DocSignHelper.Log("verifySignature finished", LogLevelEnum.Debug, null);
      return result;
    }

    public string GetDocSignServiceVersion()
    {
      var mod = System.Reflection.Assembly.GetExecutingAssembly().GetCustomAttributes(false);
      string product = null;
      string version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
      foreach (object o in mod)
      {
        var productAttr = o as AssemblyProductAttribute;
        if (productAttr != null)
          product = productAttr.Product;       
      }
      if (product != null || version != null)
        return string.Join(" ", product, version);
      return System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString();
    }
  }
}
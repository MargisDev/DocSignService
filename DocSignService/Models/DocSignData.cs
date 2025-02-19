using iTextSharp.text.pdf;
using System;
using System.Collections.Generic;

namespace DocSignService.Models
{
  public class DocSignRequest
  {
    public string AuthenticationToken { get; set; }
    public bool IsExternalSigning { get; set; }
    public string HashAlgorithm { get; set; }
    public byte[] SignerCertificate { get; set; }
    public byte[] PdfCertificate { get; set; }
    public byte[] PdfToSign { get; set; }
    public SignatureAppereanceDTO Sap { get; set; }

  }

  public class SignatureAppereanceDTO
  {
    public int Page { get; set; }
    public RectangleDTO PageRect { get; set; }
    public string FieldName { get; set; }
    public PdfDictionary CryptoDictionary { get; set; }
    public List<SignatureElementDTO> Elements { get; set; }
  }

  public class SignatureElementDTO
  {
    public byte[] Image { get; set; }
    public byte[] Pdf { get; set; }  //pdfreader byte[]
    public List<ChunkDTO> ChunkList { get; set; }
    public ColumnPositionDTO Position { get; set; }
  }

  public class ColumnPositionDTO
  {
    public float X { get; set; }
    public float Y { get; set; }
    public float Width { get; set; }
    public float Height { get; set; }
    public float Leading { get; set; }
    public int Alignment { get; set; }
  }

  public class ChunkDTO
  {
    public string Content { get; set; }
    public FontDTO Font { get; set; }
  }

  public class FontDTO
  {
    public string FontFilename { get; set; }
    public int Size { get; set; }
  }

  public class RectangleDTO
  {
    public float Left { get; set; }
    public float Right { get; set; }
    public float Top { get; set; }
    public float Bottom { get; set; }
  }

  public class DocSignResponse
  {
    public string PdfFakeSignedValue { get; set; }
    public string PdfHashToSignBase64 { get; set; }
    public string SignedPdfWithMissingSignatureB64 { get; set; }
  }

  public class VerifySignatureRequest
  {
    public byte[] PdfDocument { get; set; }
  }
  public class VerifySignatureResponse
  {
    public List<PdfPKCS7Dto> SignatureList { get; set; }
    public string ErrorMessage { get;set; }
  }

  public class PdfPKCS7Dto
  {
    public string SignatureName { get; set; }
    public bool VerifiedSignature { get; set; }
    public string VerifiedSignatureErrorMessage { get; set; }
    public bool IsValidSignature { get; set; }
    public DateTime SignDate {  get; set; }
    public byte[] SigningCertificate { get; set; }
    public string SignName { get; set; }
    public DateTime TimeStampDate { get; set; }
    public TimeStampTokenDto TimeStampToken { get; set; }
    public byte[] TimeStampTokenEncoded { get; set; }
  }  

  public class TimeStampTokenDto
  {
    public byte[] Nonce { get; set; }        
    public long Seconds { get; set; }
    public long Millis { get; set; }
    public long Micros { get; set; }
    public DateTime GeneralizedTime { get; set; }
    public string Version { get; set; }
    public bool Ordering { get; set; }
    public string PolicyId { get; set; }
    public DateTime SignDate { get; set; }
    public bool IsValidSignature { get; set; }

  }

  public enum LogLevelEnum
  {
    Always = 0,
    Error = 1,
    Debug = 2,
  }
}
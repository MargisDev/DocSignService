using DocSignService.Models;

namespace DocSignService
{
  public class SignDocService : ISignDocService
  {
    public DocSignResponse SignDoc(string input)
    {
      var request = DocSignHelper.DeserializeItemJSON(input, typeof(DocSignRequest)) as DocSignRequest;
      return SignDocProc.SignPdfDoc(request).Result;
    }
  }
}
using DocSignService.Models;
using System.ServiceModel;

namespace DocSignService
{
  [ServiceContract]
  public interface ISignDocService
  {
    [OperationContract]
    DocSignResponse SignDoc(string input);
  }
}
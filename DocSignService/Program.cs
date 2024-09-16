using System.ServiceProcess;

namespace DocSignService
{
  internal static class Program
  {
    static void Main()
    {
      ServiceBase[] ServicesToRun;
      ServicesToRun = new ServiceBase[]
      {
                new DocSignService()
      };
      ServiceBase.Run(ServicesToRun);
    }
  }
}

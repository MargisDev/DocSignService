using System.Diagnostics;
using System.ServiceModel;
using System.ServiceProcess;

namespace DocSignService
{
  public partial class DocSignService : ServiceBase
  {
    private ServiceHost serviceHost = null;

    public DocSignService()
    {
      InitializeComponent();
      ServiceName = "DocSignService";
    }

    protected override void OnStart(string[] args)
    {
      if (serviceHost != null)
      {
        serviceHost.Close();
      }

      // Create a ServiceHost for the SignDocService type and provide the base address.
      serviceHost = new ServiceHost(typeof(SignDocService));

      // Open the ServiceHost to start listening for messages.
      serviceHost.Open();

      EventLog.WriteEntry("DocSignService started successfully.");
    }

    protected override void OnStop()
    {
      if (serviceHost != null)
      {
        serviceHost.Close();
        serviceHost = null;
      }

      EventLog.WriteEntry("DocSignService stopped successfully.");
    }
  }
}

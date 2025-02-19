using System;
using System.Collections;
using System.Diagnostics;
using System.Reflection;
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

      Type type = typeof(Org.BouncyCastle.Security.SignerUtilities);
      FieldInfo info = type.GetField("algorithms", BindingFlags.NonPublic | BindingFlags.Static);
      var AlgorithmMap = (IDictionary)info.GetValue(null);
      AlgorithmMap["SHA256WITH1.2.840.10045.4.3.2"] = "SHA-256withECDSA";
      AlgorithmMap["SHA384WITH1.2.840.10045.4.3.3"] = "SHA-384withECDSA";
      AlgorithmMap["SHA384WITH1.2.840.10045.4.3.4"] = "SHA-512withECDSA";

      AppSettingsCache.PreloadAppSettings();
      serviceHost = new ServiceHost(typeof(SignDocService));
      serviceHost.Open();
    }

    protected override void OnStop()
    {
      if (serviceHost != null)
      {
        serviceHost.Close();
        serviceHost = null;
      }
    }
  }
}

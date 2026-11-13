namespace DocSignService
{
  using System;
  using System.Collections.Specialized;
  using System.Configuration;
  using System.Runtime.Caching;

  public static class AppSettingsCache
  {
    private static readonly ObjectCache Cache = MemoryCache.Default;

    public static string GetAppSetting(string key)
    {
      if (Cache.Contains(key))
        return Cache[key] as string;

      string value = ConfigurationManager.AppSettings[key];
      if (!string.IsNullOrEmpty(value))
      {
        if (key == Constants.ClientApiURL)
          value = value.TrimEnd('/') + "/";
        CacheItemPolicy policy = new CacheItemPolicy
        {
          SlidingExpiration = TimeSpan.FromDays(365)
        };
        Cache.Add(key, value, policy);
      }

      return value;
    }

    public static void PreloadAppSettings()
    {
      NameValueCollection appSettings = ConfigurationManager.AppSettings;
      foreach (string key in appSettings.AllKeys)
      {
        if (!Cache.Contains(key))
        {
          string value = appSettings[key];
          if (key == Constants.ClientApiURL)
            value = value.TrimEnd('/') + "/";
          CacheItemPolicy policy = new CacheItemPolicy
          {
            SlidingExpiration = TimeSpan.FromDays(365)
          };
          Cache.Add(key, value, policy);
        }
      }
    }
  }

}

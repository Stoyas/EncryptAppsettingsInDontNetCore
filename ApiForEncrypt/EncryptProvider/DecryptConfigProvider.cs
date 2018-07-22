using System;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Configuration;

namespace ApiForEncrypt.EncryptProvider
{
    public class DecryptConfigProvider : ConfigurationProvider
    {
        public DecryptConfigProvider()
        {
            
        }

        public override void Load()
        {
            try
            {
                string environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
                string secretFileName = $"\\appsecret.{environment}.json";
                string configFileName = $"\\appsettings.{environment}.json";
                string secretFile = string.Concat(Environment.CurrentDirectory, secretFileName);
                string configFile = string.Concat(Environment.CurrentDirectory, configFileName);
                if (!File.Exists(secretFile) || !File.Exists(configFile))
                {
                    throw new SystemException("file does not exist.");
                }
                string configContext = File.ReadAllText(configFile);
                if (configContext.Contains('#'))
                {
                    var decryptor = new Decrypter(secretFile, configFile);
                    Data = decryptor.DecryptConfig(secretFile, configFile);
                }

            }
            catch (Exception e)
            {
                throw new Exception(e.ToString());
            }
        }
    }
}

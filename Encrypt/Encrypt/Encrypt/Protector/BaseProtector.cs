using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json;

namespace Encrypt.Protector
{
    public class BaseProtector
    {
        public string Cert { get; set; }

        public BaseProtector(string secretFile, string configFile, string certFile = null)
        {
            //1. validate file
            if (String.IsNullOrEmpty(secretFile) || !File.Exists(secretFile))
            {
                throw new FileNotFoundException($"{secretFile} does not exist!");
            }
            if (String.IsNullOrEmpty(configFile) || !File.Exists(configFile))
            {
                throw new FileNotFoundException($"{secretFile} does not exist!");
            }
            //ToDo: validateFormat

            //2. Get Certificate from Local machine as key
            Cert = GetProtectorCertificate(configFile, certFile).ToString();
        }

        private X509Certificate2 GetProtectorCertificate(string configFile, string certPath = null)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            if (certPath == null)
            {
                string configContext = File.ReadAllText(configFile);
                var configDic = JsonConvert.DeserializeObject<Dictionary<string, object>>(configContext);
                var thumbprint = configDic["thumbprint"];
                var matchedCertificates = store.Certificates.Find(X509FindType.FindByThumbprint,
                    thumbprint, false);
                if (matchedCertificates.Count != 1 || matchedCertificates == null)
                {
                    throw new Exception("certificate not found.");
                }
                var targetCertificate = matchedCertificates[0];
                if (targetCertificate.NotAfter < DateTime.UtcNow)
                {
                    throw new Exception("certificate expired.");
                }
                store.Close();
                return targetCertificate;
            }
            else
            {
                if (!File.Exists(certPath))
                {
                    throw new FileNotFoundException("certificate not found.");
                }

                X509Certificate2 targetCertificate = new X509Certificate2();
                targetCertificate.Import(certPath);
                if (targetCertificate.NotAfter < DateTime.UtcNow)
                {
                    throw new Exception("certificate expired.");
                }
                store.Close();
                return targetCertificate;
            }
        }
    }
}

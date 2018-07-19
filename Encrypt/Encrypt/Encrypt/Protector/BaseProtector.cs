using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace Encrypt.Protector
{
    public class BaseProtector
    {
        public string Thumbprint { get; set; }
        public IDataProtector DataProtector { get; set; }

        public BaseProtector(string secretFile, string configFile)
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
            var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var certs = store.Certificates;
            var dataSafeCert = certs[0];
            Thumbprint = dataSafeCert.Thumbprint;

            //3. Instantiate the data protection system with thumbPrint
            var dataProtectionProvider = DataProtectionProvider.Create(
                new DirectoryInfo(Thumbprint ?? throw new InvalidOperationException()),
                configuration =>
                {
                    configuration.SetApplicationName("generate protector");
                    configuration.ProtectKeysWithDpapi();
                });

            var protector = dataProtectionProvider.CreateProtector("generate protector");

            DataProtector = protector;
        }
    }
}

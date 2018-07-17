using System;
using System.Collections;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using CommandLine;
using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Encrypt_with_Certificate
{
    class Options
    {
        public string Path { get; set; }
        public string KeyListPath { get; set; }
    }
    class BaseProtector
    {
        public IDataProtector DataProtector { get; set; }

        public BaseProtector(string inputFile)
        {
            //1. validate file
            if (String.IsNullOrEmpty(inputFile) || !File.Exists(inputFile))
            {
                throw new ArgumentNullException($"{inputFile} does not exist!");
            }
            //ToDo: validateFormat

            //2. Get Certificate from Local machine as key
            var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var certs = store.Certificates;
            var dataSafeCert = certs[0];
            var thumbprint = dataSafeCert.Thumbprint;

            //3. Instantiate the data protection system with thumbPrint
            var dataProtectionProvider = DataProtectionProvider.Create(
                new DirectoryInfo(thumbprint ?? throw new InvalidOperationException()),
                configuration =>
                {
                    configuration.SetApplicationName("generate protector");
                    configuration.ProtectKeysWithDpapi();
                });

            var protector = dataProtectionProvider.CreateProtector("generate protector");

            DataProtector = protector;
        }
    }

    class Encrpyter : BaseProtector
    {
        public Encrpyter(string inputFile) : base(inputFile)
        {
            
        }
        public string ProtectedString { get; set; }

        public void EncryptConfig(string secretFile, string configFile)
        {
            var secretJson = File.ReadAllText(secretFile);
            var configString = File.ReadAllText(configFile);
            var secretDic = JsonConvert.DeserializeObject<Dictionary<string, string>>(secretJson);
            foreach (KeyValuePair<string, string> pair in secretDic)
            {
                configString = configString.Replace(pair.Value, pair.Key);
            }
            ProtectedString = base.DataProtector.Protect(secretJson);
            // write back to config file
            File.WriteAllText(configFile,configString);
            // put protectedJson into file
            string directoryPath = String.Concat(Path.GetDirectoryName(secretFile), "\\appsecret.json");

            File.WriteAllText(directoryPath, ProtectedString);
        }
    }

    class Decrypter : BaseProtector
    {
        public Decrypter(string inputFile) : base(inputFile)
        {
        }
        public void DecryptConfig(string secretFile, string configPath)
        {
            var lookupDic = new Dictionary<string, string>();
            //1. read from secretFile
            string txt = File.ReadAllText(secretFile);
            var encryptJson = base.DataProtector.Unprotect(txt);
            var encryptDic = JsonConvert.DeserializeObject<Dictionary<string, string>>(encryptJson);

            //2. read from appsetting file
            string configString = File.ReadAllText(configPath);
            foreach (KeyValuePair<string, string> pair in encryptDic)
            {
                configString = configString.Replace(pair.Key, pair.Value);
            }

            File.WriteAllText(configPath, configString);

            File.WriteAllText(secretFile, encryptJson);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("please enter decesion: ");
            var de = Console.ReadLine();
            if (de == "e")
            {
                //encrypt
                var jsonPath = @"D:\Develop\Encrypt-appsettings\Encrypt\appsettings.json";
                var appsecretPath = @"D:\Develop\Encrypt-appsettings\Encrypt\appsecret.json";
                var encrpyter = new Encrpyter(jsonPath);
                encrpyter.EncryptConfig(appsecretPath, jsonPath);
            }
            else
            {
                //decrypt
                var encryptPath = @"D:\Develop\Encrypt-appsettings\Encrypt\appsecret.json";
                var configPath = @"D:\Develop\Encrypt-appsettings\Encrypt\appsettings.json";
                var decrypter = new Decrypter(configPath);
                decrypter.DecryptConfig(encryptPath, configPath);
            }

        }
    }
}

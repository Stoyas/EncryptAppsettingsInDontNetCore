using System;
using System.Collections;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using CommandLine;
using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json;

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
            LookupDic = new Dictionary<string, object>();
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

        //4. encrypt/decrypy with protector
        public virtual void Run(string prePath, string configPath)
        {

        }
    }

    class Encrpyter : BaseProtector
    {
        public static Dictionary<string, object> EncryptDic { get; set; }
        public static Dictionary<string, object> LookupDic { get; set; }
        public static Dictionary<string, object> ConfigDic { get; set; }


        public Encrpyter(string inputFile) : base(inputFile)
        {
            EncryptDic = new Dictionary<string, object>();
            LookupDic = new Dictionary<string, object>();
        }
        public List<string> KeyList { get; set; }
        public string ProtectedJson { get; set; }
        public override void Run(string keyList, string inputFile)
        {
            // get keys to be encrypted
            using (StreamReader reader = File.OpenText(keyList))
            {
                var jsonFile = reader.ReadToEnd();
                KeyList = JsonConvert.DeserializeObject<Dictionary<string, List<string>>>(jsonFile)["keys"];
            }

            // replace secrets in appsettings
            using (StreamReader configReader = File.OpenText(inputFile))
            {
                var configFile = configReader.ReadToEnd();
                ConfigDic = JsonConvert.DeserializeObject<Dictionary<string, object>>(configFile);
                // read from config compare with keys
                ReadFromConfig(KeyList, ConfigDic);

                ReplacingConfig(LookupDic, ConfigDic);

                var secretJson = JsonConvert.SerializeObject(EncryptDic);
                ProtectedJson = base.DataProtector.Protect(secretJson);
            }

            string newConfigJson = JsonConvert.SerializeObject(ConfigDic);
            File.WriteAllText(inputFile, newConfigJson);
            // put protectedJson into file
            string directoryPath = String.Concat(Path.GetDirectoryName(inputFile), "\\appsecret.txt");
            if (File.Exists(directoryPath))
            {
                throw new ArgumentException($"{directoryPath} already exists");
            }
            File.WriteAllText(directoryPath,ProtectedJson);
        }

        // replacing config dictionary with lookup dictionary
        private string Replace(string configFile, string secretTarget, string value)
        {
            using (File.Open(configFile) )
            {
                
            }

            var newConfig = config.Replace(secretTarget, value);
            return newConfig;
        }

        private void ReplacingConfig(Dictionary<string, object> lookupDic, Dictionary<string, object> configDic)
        {
            foreach (KeyValuePair<string, object> pair in configDictionary)
            {
                if (pair.Value is Dictionary<string, object>)
                    ReadFromConfig(keyList, (Dictionary<string, object>)pair.Value);
                else
                {
                    if (pair.Value is ICollection)
                    {
                        var counter = 0;
                        foreach (string item in (ICollection)pair.Value)
                        {
                            if (keyList.Contains(pair.Key) && !item.Contains("__"))
                            {
                                EncryptDic.Add($"__{pair.Key}{counter}__", item);
                                LookupDic.Add(pair.Key, $"__{pair.Key}{counter}__");
                                counter++;
                            }
                        }
                    }
                    else
                    {
                        if (keyList.Contains(pair.Key) && !pair.Value.ToString().Contains("__"))
                        {
                            EncryptDic.Add($"__{pair.Key}__", pair.Value);
                            LookupDic.Add(pair.Key, $"__{pair.Key}__");
                        }
                    }
                }
            }
        }

        // read from config file and return lookup dictionary
        public static void ReadFromConfig(List<string> keyList, Dictionary<string, object> configDictionary)
        {
            foreach (KeyValuePair<string, object> pair in configDictionary)
            {
                if (pair.Value is Dictionary<string, object>)
                    ReadFromConfig(keyList, (Dictionary<string, object>)pair.Value);
                else
                {
                    if (pair.Value is ICollection)
                    {
                        var counter = 0;
                        foreach (string item in (ICollection)pair.Value)
                        {
                            if (keyList.Contains(pair.Key) && !item.Contains("__"))
                            {
                                EncryptDic.Add($"__{pair.Key}{counter}__", item);
                                LookupDic.Add(pair.Key, $"__{pair.Key}{counter}__");
                                counter++;
                            }
                        }
                    }
                    else
                    {
                        if (keyList.Contains(pair.Key) && !pair.Value.ToString().Contains("__"))
                        {
                            EncryptDic.Add($"__{pair.Key}__", pair.Value);
                            LookupDic.Add(pair.Key, $"__{pair.Key}__");
                        }
                    }
                }
            }
        }

    }

    class Decrypter : BaseProtector
    {
        public Decrypter(string inputFile) : base(inputFile)
        {
        }
        public override void Run(string encryptPath, string configPath)
        {
            var lookupDic = new Dictionary<string, string>();
            //1. read from encryptPath
            string txt = File.ReadAllText(encryptPath);
            var encryptJson = base.DataProtector.Unprotect(txt);
            var encryptDic = JsonConvert.DeserializeObject<Dictionary<string, string>>(encryptJson);
            Dictionary<string, string> configDic;

            //2. read from appsetting file
            using (StreamReader configReader = File.OpenText(configPath))
            {
                var configFile = configReader.ReadToEnd();
                configDic = JsonConvert.DeserializeObject<Dictionary<string, string>>(configFile);
                // look up
                foreach (var key in configDic.Keys)
                {
                    if (encryptDic.ContainsKey(configDic[key]))
                    {
                        lookupDic.Add(key, encryptDic[configDic[key]]);
                    }
                }
                // replacing
                foreach (var key in lookupDic.Keys)
                {
                    configDic[key] = lookupDic[key];
                }
            }

            string newConfigJson = JsonConvert.SerializeObject(configDic);
            File.WriteAllText(configPath, newConfigJson);
            
            // remove encryption file
            File.Delete(encryptPath);
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
                var listPath = @"D:\Develop\Encrypt-appsettings\Encrypt\KeyList.json";
                var jsonPath = @"D:\Develop\Encrypt-appsettings\Encrypt\appsettings.Development.json";
                var encrpyter = new Encrpyter(jsonPath);
                encrpyter.Run(listPath, jsonPath);
            }
            else
            {
                //decrypt
                var encryptPath = @"D:\Develop\Encrypt-appsettings\Encrypt\appsecret.txt";
                var configPath = @"D:\Develop\Encrypt-appsettings\Encrypt\appsettings.Development.json";
                var decrypter = new Decrypter(configPath);
                decrypter.Run(encryptPath, configPath);
            }

        }
    }
}

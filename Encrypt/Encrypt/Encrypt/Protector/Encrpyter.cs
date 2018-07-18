using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Encrypt.Protector
{
    public class Encrpyter : BaseProtector
    {
        public Encrpyter(string secretFile, string configFile) : base(secretFile, configFile)
        {
        }
        public string ProtectedString { get; set; }

        public void EncryptConfig(string secretFile, string configFile)
        {
            try
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
                File.WriteAllText(configFile, configString);
                // put protectedJson into file
                File.WriteAllText(secretFile, ProtectedString);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }
}

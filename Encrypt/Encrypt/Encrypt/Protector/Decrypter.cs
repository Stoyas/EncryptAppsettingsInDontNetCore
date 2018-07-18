using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Encrypt.Protector
{
    public class Decrypter : BaseProtector
    {
        public Decrypter(string secretFile, string configFile) : base(secretFile, configFile)
        {
        }
        public void DecryptConfig(string secretFile, string configPath)
        {
            try
            {
                //1. read from secretFile
                string txt = File.ReadAllText(secretFile);
                var encryptJson = base.DataProtector.Unprotect(txt);
                var encryptDic = JsonConvert.DeserializeObject<Dictionary<string, string>>(encryptJson);

                //2. read from appsettings file
                string configString = File.ReadAllText(configPath);
                foreach (KeyValuePair<string, string> pair in encryptDic)
                {
                    configString = configString.Replace(pair.Key, pair.Value);
                }

                File.WriteAllText(configPath, configString);

                File.WriteAllText(secretFile, encryptJson);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

        }
    }
}

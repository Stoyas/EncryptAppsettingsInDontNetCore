using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Encrypt.Protector
{
    public class Encrypter : BaseProtector
    {
        public Encrypter(string secretFile, string configFile, string certFile = null) : base(secretFile, configFile, certFile)
        {
        }
        public string ProtectedString { get; set; }

        public void EncryptConfig(string secretFile, string configFile)
        {
            try
            {
                var secretJson = File.ReadAllText(secretFile);
                var configString = File.ReadAllText(configFile);
                if (configString.Contains('#'))
                {
                    throw new Exception("config file is already encrypted.");
                }
                var secretDic = JsonConvert.DeserializeObject<Dictionary<string, string>>(secretJson);
                foreach (KeyValuePair<string, string> pair in secretDic)
                {
                    configString = configString.Replace(pair.Value, pair.Key);
                }

                ProtectedString = Encrypt(secretJson, base.Cert);
                // write back to config file
                File.WriteAllText(configFile, configString);
                // put protectedJson into file
                File.WriteAllText(secretFile, ProtectedString);
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        public static string Encrypt(string plainText, string password,
            string salt = "Starbucks", string hashAlgorithm = "SHA256",
            int passwordIterations = 2, string initialVector = "YeGWeh26(oHLvy&Y",
            int keySize = 256)
        {
            if (string.IsNullOrEmpty(plainText))
                return "";
            byte[] initialVectorBytes = Encoding.ASCII.GetBytes(initialVector);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(salt);
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            PasswordDeriveBytes derivedPassword = new PasswordDeriveBytes(password, saltValueBytes, hashAlgorithm, passwordIterations);
            byte[] keyBytes = derivedPassword.GetBytes(keySize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;
            byte[] cipherTextBytes = null;
            using (ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initialVectorBytes))
            {
                using (MemoryStream memStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        cipherTextBytes = memStream.ToArray();
                        memStream.Close();
                        cryptoStream.Close();
                    }
                }
            }

            symmetricKey.Clear();
            return Convert.ToBase64String(cipherTextBytes);
        }
    }
}

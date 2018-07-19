using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

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
                //var encryptJson = base.DataProtector.Unprotect(txt);
                var encryptJson = Decrypt(txt, base.Thumbprint);
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

        public static string Decrypt(string cipherText, string password,
            string salt = "Kosher", string hashAlgorithm = "SHA1",
            int passwordIterations = 2, string initialVector = "OFRna73m*aze01xY",
            int keySize = 256)
        {
            if (string.IsNullOrEmpty(cipherText))
                return "";
            byte[] initialVectorBytes = Encoding.ASCII.GetBytes(initialVector);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(salt);
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
            PasswordDeriveBytes derivedPassword =
                new PasswordDeriveBytes(password, saltValueBytes, hashAlgorithm, passwordIterations);
            byte[] keyBytes = derivedPassword.GetBytes(keySize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];
            int byteCount = 0;
            using (ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initialVectorBytes))
            {
                using (MemoryStream memStream = new MemoryStream(cipherTextBytes))
                {
                    using (CryptoStream cryptoStream =
                        new CryptoStream(memStream, decryptor, CryptoStreamMode.Read))
                    {

                        byteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                        memStream.Close();
                        cryptoStream.Close();
                    }
                }
            }

            symmetricKey.Clear();
            return Encoding.UTF8.GetString(plainTextBytes, 0, byteCount);
        }
    }
}

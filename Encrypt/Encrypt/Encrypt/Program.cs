using System;
using System.ComponentModel;
using Encrypt.Protector;

namespace Encrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                if (args.Length < 3)
                {
                    throw new ArgumentException($"invalid input");
                }

                var secretFile = args[1];
                var configFile = args[2];

                if (args[0] == "e")
                {
                    var encrpyter = new Encrypter(secretFile, configFile);
                    encrpyter.EncryptConfig(secretFile, configFile);
                    Console.WriteLine("Encryption completed!");
                }
                else if (args[0] == "d")
                {
                    var decrypter = new Decrypter(secretFile, configFile);
                    decrypter.DecryptConfig(secretFile, configFile);
                    Console.WriteLine("Decryption completed!");
                }
                else
                {
                    throw new ArgumentException($"'{args[0]}' is not a valid action type.");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.ReadKey();
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace AesSample
{
    internal class Program
    {
        static void Main(string[] args)
        {
            byte[] key = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            };

            byte[] iv = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };

            Aes256Handler aes256Handler = new Aes256Handler(key,iv);

            string ori,enc, dec;
            //enc = aes256Handler.EncryptString("asdfghjkl");
            ori = "AQIDBAUGBwgJAAECAwQFBg==";
            enc = aes256Handler.EncryptString2(ori,PaddingMode.PKCS7);
            dec = aes256Handler.DecryptString2(enc, PaddingMode.PKCS7);

            Console.WriteLine("ori:" + ori);
            Console.WriteLine("enc:" + enc);
            Console.WriteLine("dec:" + dec);

            Console.ReadLine();
        }
    }

    public class Aes256Handler
    {
        private byte[] key { get; set; }
        private byte[] iv { get; set; }

        private PaddingMode mode { get; set; }

        public Aes256Handler(byte[] key, byte[] iv)
        {
            this.key = key;
            this.iv = iv;
            this.mode = PaddingMode.None;
        }
        public string EncryptString2(string plaintext, PaddingMode mode)
        {
            this.mode = mode;
            return Convert.ToBase64String(Encrypt(Convert.FromBase64String(plaintext)));
        }
        public string DecryptString2(string encryptedtext, PaddingMode mode)
        {
            this.mode = mode;
            return Convert.ToBase64String(Decrypt(Convert.FromBase64String(encryptedtext)));
        }

        public string EncryptString(string plaintext)
        {
            return Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(plaintext)));
        }

        public string DecryptString(string encryptedtext)
        {
            return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(encryptedtext)));
        }

        public byte[] Encrypt(byte[] bytes)
        {
            if (bytes == null || bytes.Length < 1)
            {
                throw new ArgumentException("Invalid bytes");
            }

            if (key == null || key.Length < 1)
            {
                throw new InvalidOperationException("Invalid encryption settings");
            }

            byte[] encrypted;

            try
            {
                //using (Aes aes = Aes.Create())
                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    //aes.Padding = PaddingMode.None;
                    //aes.Padding = PaddingMode.PKCS7;
                    aes.Padding = mode;

                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(bytes, 0, bytes.Length);
                        }

                        encrypted = ms.ToArray();
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            return encrypted;
        }

        public byte[] Decrypt(byte[] bytes)
        {
            if (bytes == null || bytes.Length < 1)
            {
                throw new ArgumentException("Invalid bytes");
            }

            if (key == null || key.Length < 1)
            {
                throw new InvalidOperationException("Invalid encryption settings");
            }

            byte[] decrypted;

            try
            {
                //using (Aes aes = Aes.Create())
                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    //aes.Padding = PaddingMode.None;
                    //aes.Padding = PaddingMode.PKCS7;
                    aes.Padding = mode;

                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, iv);

                    using (MemoryStream ms = new MemoryStream(bytes))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            decrypted = new byte[bytes.Length];
                            var decryptedCount = cs.Read(decrypted, 0, decrypted.Length);
                            decrypted = decrypted.Take(decryptedCount).ToArray();

                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            return decrypted;
        }
    }
}

//using System;
//using System.IO;
//using System.Security.Cryptography;

//namespace Aes_Example
//{
//    class AesExample
//    {
//        public static void Main()
//        {
//            string original = "Here is some data to encrypt!";

//            // Create a new instance of the Aes
//            // class.  This generates a new key and initialization
//            // vector (IV).
//            using (Aes myAes = Aes.Create())
//            {

//                // Encrypt the string to an array of bytes.
//                byte[] encrypted = EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);

//                // Decrypt the bytes to a string.
//                string roundtrip = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

//                //Display the original data and the decrypted data.
//                Console.WriteLine("Original:   {0}", original);
//                Console.WriteLine("Round Trip: {0}", roundtrip);
//            }
//        }
//        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
//        {
//            // Check arguments.
//            if (plainText == null || plainText.Length <= 0)
//                throw new ArgumentNullException("plainText");
//            if (Key == null || Key.Length <= 0)
//                throw new ArgumentNullException("Key");
//            if (IV == null || IV.Length <= 0)
//                throw new ArgumentNullException("IV");
//            byte[] encrypted;

//            // Create an Aes object
//            // with the specified key and IV.
//            using (Aes aesAlg = Aes.Create())
//            {
//                aesAlg.Key = Key;
//                aesAlg.IV = IV;

//                // Create an encryptor to perform the stream transform.
//                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

//                // Create the streams used for encryption.
//                using (MemoryStream msEncrypt = new MemoryStream())
//                {
//                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
//                    {
//                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
//                        {
//                            //Write all data to the stream.
//                            swEncrypt.Write(plainText);
//                        }
//                        encrypted = msEncrypt.ToArray();
//                    }
//                }
//            }

//            // Return the encrypted bytes from the memory stream.
//            return encrypted;
//        }

//        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
//        {
//            // Check arguments.
//            if (cipherText == null || cipherText.Length <= 0)
//                throw new ArgumentNullException("cipherText");
//            if (Key == null || Key.Length <= 0)
//                throw new ArgumentNullException("Key");
//            if (IV == null || IV.Length <= 0)
//                throw new ArgumentNullException("IV");

//            // Declare the string used to hold
//            // the decrypted text.
//            string plaintext = null;

//            // Create an Aes object
//            // with the specified key and IV.
//            using (Aes aesAlg = Aes.Create())
//            {
//                aesAlg.Key = Key;
//                aesAlg.IV = IV;

//                // Create a decryptor to perform the stream transform.
//                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

//                // Create the streams used for decryption.
//                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
//                {
//                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
//                    {
//                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
//                        {

//                            // Read the decrypted bytes from the decrypting stream
//                            // and place them in a string.
//                            plaintext = srDecrypt.ReadToEnd();
//                        }
//                    }
//                }
//            }

//            return plaintext;
//        }
//    }
//}

//https://stackoverflow.com/questions/54939489/aes-256-encryption-cant-get-iv-from-byte-array-correctly

//using System;
//using System.Text;
//using System.IO;
//using System.Linq;
//using System.Security.Cryptography;
//namespace EncryptionTest
//{
//    public class Aes256Handler
//    {
//        private byte[] key;

//        public Aes256Handler(byte[] key)
//        {
//            this.key = key;
//        }

//        public string EncryptString(string plaintext)
//        {
//            return Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(plaintext)));
//        }

//        public string DecryptString(string encryptedtext)
//        {
//            return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(encryptedtext)));
//        }

//        public byte[] Encrypt(byte[] bytes)
//        {
//            if (bytes == null || bytes.Length < 1)
//            {
//                throw new ArgumentException("Invalid bytes");
//            }

//            if (key == null || key.Length < 1)
//            {
//                throw new InvalidOperationException("Invalid encryption settings");
//            }

//            byte[] encrypted;

//            try
//            {
//                using (Aes aes = Aes.Create())
//                {
//                    aes.Key = key;
//                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

//                    using (MemoryStream ms = new MemoryStream())
//                    {
//                        ms.Write(aes.IV, 0, aes.IV.Length);

//                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
//                        {
//                            cs.Write(bytes, 0, bytes.Length);
//                        }

//                        encrypted = ms.ToArray();
//                    }
//                }
//            }
//            catch (Exception e)
//            {
//                Console.WriteLine(e);
//                throw;
//            }

//            return encrypted;
//        }

//        public byte[] Decrypt(byte[] bytes)
//        {
//            if (bytes == null || bytes.Length < 1)
//            {
//                throw new ArgumentException("Invalid bytes");
//            }

//            if (key == null || key.Length < 1)
//            {
//                throw new InvalidOperationException("Invalid encryption settings");
//            }

//            byte[] decrypted;

//            try
//            {
//                using (Aes aes = Aes.Create())
//                {
//                    aes.Key = key;
//                    byte[] iv = new byte[16];
//                    MemoryStream ms = new MemoryStream(bytes);
//                    ms.Read(iv, 0, iv.Length);
//                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, iv);

//                    using (ms)
//                    {
//                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
//                        {
//                            decrypted = new byte[bytes.Length - iv.Length];
//                            var decryptedCount = cs.Read(decrypted, 0, decrypted.Length);
//                            decrypted = decrypted.Take(decryptedCount).ToArray();

//                        }
//                    }
//                }
//            }
//            catch (Exception e)
//            {
//                Console.WriteLine(e);
//                throw;
//            }

//            return decrypted;
//        }
//    }
//}
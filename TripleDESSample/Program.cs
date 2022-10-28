//#define TEST_ENV
//#define PROD_ENV

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Reflection;

//https://www.c-sharpcorner.com/article/tripledes-encryption-in-c-sharp/

//weakKey
//https://stackoverflow.com/questions/37542102/decrypting-tripledes-specified-key-is-a-known-weak-key-and-cannot-be-used
namespace TripleDESSample
{
    internal class Program
    {
        static byte[] data = {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
            };

        static byte[] key = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            };

        static byte[] iv = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };

        static void Main(string[] args)
        {
            //Console.WriteLine("Enter text that needs to be encrypted..");
            //string data = Console.ReadLine();

            string ori = "AQIDBAUGBwgJAAECAwQFBg==";
            Console.WriteLine("ori:" + ori);
            TripleDESSample tripleDESSample = new TripleDESSample();
            tripleDESSample.Apply3DES2(ori);
            Console.ReadLine();
        }
        
    }

    class TripleDESSample
    {
        byte[] key = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            };

        byte[] iv = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };

#if (TEST_ENV)
        public static void Test()
        {
            byte[] Key = new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
            byte[] IV = new byte[8];
            TripleDES tripleDESalg = TripleDES.Create();
            TripleDESCryptoServiceProvider sm = tripleDESalg as TripleDESCryptoServiceProvider;
            sm.Mode = CipherMode.CBC;
            sm.Padding = PaddingMode.None;
            MethodInfo mi = sm.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] Par = { Key, sm.Mode, IV, sm.FeedbackSize, 0 };
            ICryptoTransform trans = mi.Invoke(sm, Par) as ICryptoTransform;
            //            byte[] data = new byte[8] { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
            byte[] data = {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
            };
            byte[] result = new byte[8];
            result = trans.TransformFinalBlock(data, 0, 8);

            Console.WriteLine("result:"+Convert.ToBase64String(result));
        }

        public byte[] Encrypt3(byte[] bytes)
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
                using(TripleDES dES = TripleDES.Create())
                {

                    TripleDESCryptoServiceProvider sm = dES as TripleDESCryptoServiceProvider;
                    sm.Mode = CipherMode.CBC;
                    sm.Padding = PaddingMode.None;
                    MethodInfo mi = sm.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
                    object[] Par = { key, sm.Mode, iv, sm.FeedbackSize, 0 };
                    ICryptoTransform trans = mi.Invoke(sm, Par) as ICryptoTransform;

                    //dES.Key = key;
                    //dES.IV = iv;
                    //dES.Mode = CipherMode.CBC;
                    //dES.Padding = PaddingMode.None;

                    //ICryptoTransform encryptor = dES.CreateEncryptor(dES.Key, dES.IV);

                    using(MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, trans, CryptoStreamMode.Write))
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

#else
#endif

        public void Apply3DES2(string raw)
        {

            try
            {
                // Create 3DES that generates a new key and initialization vector (IV).  
                // Same key must be used in encryption and decryption  
                // Encrypt string  
                //tdes.Key:3qHENE6h/c86zm9k2qDoRTHDjrwIyl3U
                //tdes.IV:lwDjWN7uNh4=
                byte[] sKey = Convert.FromBase64String("3qHENE6h/c86zm9k2qDoRTHDjrwIyl3U");
                byte[] sIV = Convert.FromBase64String("lwDjWN7uNh4=");
                //byte[] encrypted = Encrypt2(Convert.FromBase64String(raw), sKey, sIV);
                byte[] encrypted = Encrypt2(Convert.FromBase64String(raw), key, iv);
                // Print encrypted string  
                string encryptedB = Convert.ToBase64String(encrypted);
                Console.WriteLine("Encrypted data:" + encryptedB);
                // Decrypt the bytes to a string.  
                //byte[] decrypted = Decrypt2(encrypted, sKey, sIV);
                byte[] decrypted = Decrypt2(encrypted, key, iv);
                // Print decrypted string. It should be same as raw data  
                Console.WriteLine("Decrypted data:" + Convert.ToBase64String(decrypted));
            }
            catch (Exception exp)
            {
                Console.WriteLine(exp.Message);
            }
            Console.ReadKey();
        }

        
        byte[] Encrypt2(byte[] plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            // Create a new TripleDESCryptoServiceProvider.  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            if (true)
            {
                tdes.Mode = CipherMode.CBC;
                tdes.Padding = PaddingMode.None;
                // Create encryptor  
                //ICryptoTransform encryptor = tdes.CreateEncryptor(Key, IV);
                ICryptoTransform encryptor = tdes.CreateWeakEncryptor(Key, IV);
                // Create MemoryStream  
                using (MemoryStream ms = new MemoryStream())
                {
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption  
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream  
                    // to encrypt  
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(plainText, 0, plainText.Length);
                        //// Create StreamWriter and write data to a stream  
                        //using (StreamWriter sw = new StreamWriter(cs))
                        //    sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            // Return encrypted data  
            return encrypted;
        }

        byte[] Decrypt2(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            byte[] decrypted;
            // Create TripleDESCryptoServiceProvider  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.CBC;
                tdes.Padding = PaddingMode.None;
                // Create a decryptor  
                //ICryptoTransform decryptor = tdes.CreateDecryptor(Key, IV);
                ICryptoTransform decryptor = tdes.CreateWeakDecryptor(Key, IV);
                // Create the streams used for decryption.  
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Create crypto stream  
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        decrypted = new byte[cipherText.Length];
                        var decryptedCount = cs.Read(decrypted, 0, decrypted.Length);
                        decrypted = decrypted.Take(decryptedCount).ToArray();
                        //// Read crypto stream  
                        //using (StreamReader reader = new StreamReader(cs))
                        //    plaintext = reader.ReadToEnd();
                    }
                }
            }
            return decrypted;
        }

        public void Apply3DES(string raw)
        {
            try
            {
                // Create 3DES that generates a new key and initialization vector (IV).  
                // Same key must be used in encryption and decryption  
                using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
                {
                    // Encrypt string
                    Console.WriteLine("tdes.Key:" + Convert.ToBase64String(tdes.Key));
                    Console.WriteLine("tdes.IV:" + Convert.ToBase64String(tdes.IV));
                    byte[] encrypted = Encrypt(raw, tdes.Key, tdes.IV);
                    // Print encrypted string  
                    Console.WriteLine("Encrypted data:" + Encoding.UTF8.GetString(encrypted));
                    // Decrypt the bytes to a string.  
                    string decrypted = Decrypt(encrypted, tdes.Key, tdes.IV);
                    // Print decrypted string. It should be same as raw data  
                    Console.WriteLine("Decrypted data:" + decrypted);
                }
            }
            catch (Exception exp)
            {
                Console.WriteLine(exp.Message);
            }
            Console.ReadKey();
        }

        byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            // Create a new TripleDESCryptoServiceProvider.  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                // Create encryptor  
                ICryptoTransform encryptor = tdes.CreateEncryptor(Key, IV);
                // Create MemoryStream  
                using (MemoryStream ms = new MemoryStream())
                {
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption  
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream  
                    // to encrypt  
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // Create StreamWriter and write data to a stream  
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            // Return encrypted data  
            return encrypted;
        }
        string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            // Create TripleDESCryptoServiceProvider  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                // Create a decryptor  
                ICryptoTransform decryptor = tdes.CreateDecryptor(Key, IV);
                // Create the streams used for decryption.  
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Create crypto stream  
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Read crypto stream  
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();
                    }
                }
            }
            return plaintext;
        }
        private void EncryptFile(String inName, String outName, byte[] desKey, byte[] desIV)
        {
            //Create the file streams to handle the input and output files.  
            FileStream fin = new FileStream(inName, FileMode.Open, FileAccess.Read);
            FileStream fout = new FileStream(outName, FileMode.OpenOrCreate, FileAccess.Write);
            fout.SetLength(0);
            //Create variables to help with read and write.  
            byte[] bin = new byte[100]; //This is intermediate storage for the encryption.  
            long rdlen = 0; //This is the total number of bytes written.  
            long totlen = fin.Length; //This is the total length of the input file.  
            int len; //This is the number of bytes to be written at a time.  
            DES des = new DESCryptoServiceProvider();
            CryptoStream encStream = new CryptoStream(fout, des.CreateEncryptor(desKey, desIV), CryptoStreamMode.Write);
            Console.WriteLine("Encrypting...");
            //Read from the input file, then encrypt and write to the output file.  
            while (rdlen < totlen)
            {
                len = fin.Read(bin, 0, 100);
                encStream.Write(bin, 0, len);
                rdlen = rdlen + len;
                Console.WriteLine("{0} bytes processed", rdlen);
            }
            encStream.Close();
            fout.Close();
            fin.Close();
        }

    }
}

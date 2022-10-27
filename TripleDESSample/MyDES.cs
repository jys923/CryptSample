using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Reflection;

namespace TripleDESSample
{
    //internal class MyDES
    //{
    //}

    static class MyDES
    {
        public static byte[] Encrypt(byte[] data, byte[] key, byte[] IV)
        {
            MemoryStream mStream = new MemoryStream();
            TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
            des.Mode = CipherMode.CBC;
            des.Padding = PaddingMode.None;
            CryptoStream cStream = new CryptoStream(mStream,
                des.CreateWeakEncryptor(key, IV),
                CryptoStreamMode.Write);
            cStream.Write(data, 0, data.Length);
            cStream.FlushFinalBlock();
            byte[] ret = mStream.ToArray();
            cStream.Close();
            mStream.Close();
            return ret;
        }

        public static byte[] Decrypt(byte[] data, byte[] key, byte[] IV)
        {
            MemoryStream msDecrypt = new MemoryStream(data);
            TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
            des.Mode = CipherMode.CBC;
            des.Padding = PaddingMode.None;
            CryptoStream csDecrypt = new CryptoStream(msDecrypt,
                des.CreateWeakDecryptor(key, IV),
                CryptoStreamMode.Read);
            byte[] fromEncrypt = new byte[data.Length];
            csDecrypt.Read(fromEncrypt, 0, fromEncrypt.Length);
            return fromEncrypt;
        }


        #region TripleDESCryptoExtensions
        public static ICryptoTransform CreateWeakEncryptor(this TripleDESCryptoServiceProvider cryptoProvider, byte[] key, byte[] iv)
        {
            // reflective way of doing what CreateEncryptor() does, bypassing the check for weak keys
            MethodInfo mi = cryptoProvider.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] Par = { key, cryptoProvider.Mode, iv, cryptoProvider.FeedbackSize, 0 };
            ICryptoTransform trans = mi.Invoke(cryptoProvider, Par) as ICryptoTransform;
            return trans;
        }

        public static ICryptoTransform CreateWeakEncryptor(this TripleDESCryptoServiceProvider cryptoProvider)
        {
            return CreateWeakEncryptor(cryptoProvider, cryptoProvider.Key, cryptoProvider.IV);
        }

        public static ICryptoTransform CreateWeakDecryptor(this TripleDESCryptoServiceProvider cryptoProvider, byte[] key, byte[] iv)
        {
            // reflective way of doing what CreateDecryptor() does, bypassing the check for weak keys
            MethodInfo mi = cryptoProvider.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] Par = { key, cryptoProvider.Mode, iv, cryptoProvider.FeedbackSize, 1 };
            ICryptoTransform trans = mi.Invoke(cryptoProvider, Par) as ICryptoTransform;
            return trans;
        }

        public static ICryptoTransform CreateWeakDecryptor(this TripleDESCryptoServiceProvider cryptoProvider)
        {
            return CreateWeakDecryptor(cryptoProvider, cryptoProvider.Key, cryptoProvider.IV);
        }
        #endregion
    }
}

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DataEncryptionDemo.Helpers
{
    public static class EncryptionHelper
    {
        #region AesEncryption

        public static string AesEncrypt(this string text, string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key must have valid value.", nameof(key));
            if (string.IsNullOrEmpty(text))
                throw new ArgumentException("The text must have valid value.", nameof(text));

            var buffer = Encoding.UTF8.GetBytes(text);
            var hash = new SHA512CryptoServiceProvider();
            var aesKey = new byte[32];
            Buffer.BlockCopy(hash.ComputeHash(Encoding.UTF8.GetBytes(key)), 0, aesKey, 0, 32);

            using (var aes = Aes.Create())
            {
                if (aes == null)
                    throw new ArgumentException("Parameter must not be null.", nameof(aes));

                aes.Key = aesKey;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var resultStream = new MemoryStream())
                {
                    using (var aesStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
                    using (var plainStream = new MemoryStream(buffer))
                    {
                        plainStream.CopyTo(aesStream);
                    }

                    var result = resultStream.ToArray();
                    var combined = new byte[aes.IV.Length + result.Length];
                    Array.ConstrainedCopy(aes.IV, 0, combined, 0, aes.IV.Length);
                    Array.ConstrainedCopy(result, 0, combined, aes.IV.Length, result.Length);

                    return Convert.ToBase64String(combined);
                }
            }
        }

        public static string AesDecrypt(this string encryptedText, string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key must have valid value.", nameof(key));
            if (string.IsNullOrEmpty(encryptedText))
                throw new ArgumentException("The encrypted text must have valid value.", nameof(encryptedText));

            var combined = Convert.FromBase64String(encryptedText);
            var buffer = new byte[combined.Length];
            var hash = new SHA512CryptoServiceProvider();
            var aesKey = new byte[32];
            Buffer.BlockCopy(hash.ComputeHash(Encoding.UTF8.GetBytes(key)), 0, aesKey, 0, 32);

            using (var aes = Aes.Create())
            {
                if (aes == null)
                    throw new ArgumentException("Parameter must not be null.", nameof(aes));

                aes.Key = aesKey;

                var iv = new byte[aes.IV.Length];
                var ciphertext = new byte[buffer.Length - iv.Length];

                Array.ConstrainedCopy(combined, 0, iv, 0, iv.Length);
                Array.ConstrainedCopy(combined, iv.Length, ciphertext, 0, ciphertext.Length);

                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var resultStream = new MemoryStream())
                {
                    using (var aesStream = new CryptoStream(resultStream, decryptor, CryptoStreamMode.Write))
                    using (var plainStream = new MemoryStream(ciphertext))
                    {
                        plainStream.CopyTo(aesStream);
                    }

                    return Encoding.UTF8.GetString(resultStream.ToArray());
                }
            }
        }

        #endregion AesEncryption

        #region Encryption with certificate

        public static string Encrypt(this string value)
        {
            X509Certificate2 myCert = LoadCertificate(StoreLocation.LocalMachine, "DataEncryption");
            return Encrypt(myCert, value);
        }

        public static string Encrypt(X509Certificate2 x509, string stringToEncrypt)
        {
            return Convert.ToBase64String(EncryptToByteArray(x509, stringToEncrypt));
        }

        public static byte[] EncryptToByteArray(this string stringToEncrypt)
        {
            X509Certificate2 myCert = LoadCertificate(StoreLocation.LocalMachine, "DataEncryption");
            return EncryptToByteArray(myCert, stringToEncrypt);
        }

        public static byte[] EncryptToByteArray(X509Certificate2 x509, string stringToEncrypt)
        {
            if (x509 == null || string.IsNullOrEmpty(stringToEncrypt))
                throw new Exception("A x509 certificate and string for encryption must be provided");
            using (var rsa = x509.GetRSAPublicKey())
            {
                byte[] bytestoEncrypt = Encoding.UTF8.GetBytes(stringToEncrypt);

                var encryptedBytes = rsa.Encrypt(bytestoEncrypt, RSAEncryptionPadding.OaepSHA256);

                return encryptedBytes;
            }
        }

        public static string Decrypt(this string value)
        {
            X509Certificate2 myCert = LoadCertificate(StoreLocation.LocalMachine, "DataEncryption");
            return Decrypt(myCert, value);
        }

        public static string Decrypt(X509Certificate2 x509, string stringTodecrypt)
        {
            if (x509 == null || string.IsNullOrEmpty(stringTodecrypt))
                throw new Exception("A x509 certificate and string for decryption must be provided");

            if (!x509.HasPrivateKey)
                throw new Exception("x509 certicate does not contain a private key for decryption");

            using (var rsa = x509.GetRSAPrivateKey())
            {
                byte[] bytestodecrypt = Convert.FromBase64String(stringTodecrypt);
                byte[] plainbytes = rsa.Decrypt(bytestodecrypt, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(plainbytes);
            }
        }

        public static string DecryptFromByteArray(this byte[] bytesToDecrypt)
        {
            X509Certificate2 myCert = LoadCertificate(StoreLocation.LocalMachine, "DataEncryption");
            return DecryptFromByteArray(myCert, bytesToDecrypt);
        }

        public static string DecryptFromByteArray(X509Certificate2 x509, byte[] bytesToDecrypt)
        {
            if (x509 == null || bytesToDecrypt == null)
                throw new Exception("A x509 certificate and string for decryption must be provided");

            if (!x509.HasPrivateKey)
                throw new Exception("x509 certicate does not contain a private key for decryption");

            using (var rsa = x509.GetRSAPrivateKey())
            {
                byte[] plainbytes = rsa.Decrypt(bytesToDecrypt, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(plainbytes);
            }
        }

        private static X509Certificate2 LoadCertificate(StoreLocation storeLocation, string certificateName)
        {
            X509Store store = new X509Store(storeLocation);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection = store.Certificates;
            X509Certificate2 cert = certCollection.Cast<X509Certificate2>().FirstOrDefault(c => c.FriendlyName == certificateName);
            if (cert == null)
                Console.WriteLine("NO Certificate named " +
                   certificateName + " was found in your certificate store");
            store.Close();
            return cert;
        }

        #endregion Encryption with certificate
    }
}
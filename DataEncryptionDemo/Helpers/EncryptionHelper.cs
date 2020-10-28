using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DataEncryptionDemo.Helpers
{
    public class EncryptionHelper
    {
        public static string Encrypt(string value)
        {
            X509Certificate2 myCert = LoadCertificate(StoreLocation.LocalMachine, "DataEncryption");
            return Encrypt(myCert, value);
        }

        public static string Encrypt(X509Certificate2 x509, string stringToEncrypt)
        {
            if (x509 == null || string.IsNullOrEmpty(stringToEncrypt))
                throw new Exception("A x509 certificate and string for encryption must be provided");
            using (var rsa = x509.GetRSAPublicKey())
            {
                byte[] bytestoEncrypt = Encoding.UTF8.GetBytes(stringToEncrypt);

                var encryptedBytes = rsa.Encrypt(bytestoEncrypt, RSAEncryptionPadding.OaepSHA256);

                return Convert.ToBase64String(encryptedBytes);
            }
        }

        public static byte[] EncryptToByteArray(string stringToEncrypt)
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

        public static string Decrypt(string value)
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
                return Encoding.ASCII.GetString(plainbytes);
            }
        }

        public static string DecryptFromByteArray(byte[] bytesToDecrypt)
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
                return Encoding.ASCII.GetString(plainbytes);
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
    }
}
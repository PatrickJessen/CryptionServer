using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace CryptionServer
{
    public class SessionKey
    {
        public byte[] SymmetricKey;
        public RSAParameters PublicKey;
        public RSAParameters PrivateKey;
    }
    public class RSACrypter
    {
        public SessionKey sesKey;

        public RSACrypter()
        {
            sesKey = new SessionKey();
        }

        public byte[] GenerateAndEncryptSessionKey()
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = aes.LegalKeySizes[0].MaxSize;

                sesKey.SymmetricKey = aes.Key;
            }

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(sesKey.PublicKey);

                byte[] buffer = rsa.Encrypt(sesKey.SymmetricKey, false);
                return buffer;
            }
        }

        public void GetPublicKey(string key)
        {
            StringReader sr = new StringReader(key);
            XmlSerializer xs = new XmlSerializer(typeof(RSAParameters));
            sesKey.PublicKey = (RSAParameters)xs.Deserialize(sr);
        }

        public void SetSymmetricKey(Guid id, byte[] encryptedKey)
        {
            SessionKey session = sesKey;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(session.PrivateKey);

                session.SymmetricKey = rsa.Decrypt(encryptedKey, false);
            }
        }

        public byte[] EncryptData(byte[] key, string data)
        {
            using (Aes aes = Aes.Create())
            {
                byte[] result;

                aes.Key = key;
                aes.GenerateIV();

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter writer = new StreamWriter(cs))
                            {
                                writer.Write(data);
                            }
                        }

                        byte[] encrypted = ms.ToArray();
                        result = new byte[aes.BlockSize / 8 + encrypted.Length];

                        // Result is built as: IV (plain text) + Encrypted(data)
                        Array.Copy(aes.IV, result, aes.BlockSize / 8);
                        Array.Copy(encrypted, 0, result, aes.BlockSize / 8, encrypted.Length);

                        return result;
                    }
                }
            }
        }

        public string Decrypt(byte[] key, byte[] data)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;

                // Extract the IV from the data first.
                byte[] iv = new byte[aes.BlockSize / 8];
                Array.Copy(data, iv, iv.Length);
                aes.IV = iv;

                // The remainder of the data is the encrypted data we care about.
                byte[] encryptedData = new byte[data.Length - iv.Length];
                Array.Copy(data, iv.Length, encryptedData, 0, encryptedData.Length);

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    using (MemoryStream ms = new MemoryStream(encryptedData))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader reader = new StreamReader(cs))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }
    }
}

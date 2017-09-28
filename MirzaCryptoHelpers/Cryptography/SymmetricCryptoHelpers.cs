using System;
using System.Text;
using System.Security.Cryptography;

namespace MirzaCryptoHelpers.Cryptography
{
    public class SymmetricCryptoHelpers
    {
        #region AES Encryption-Decryption
        /// <summary>
        /// 16-Bytes Static IV
        /// </summary>
        private static byte[] _iv =
            new byte[16] { 167, 245, 228, 97, 198, 77, 200, 142, 174, 229, 254, 127, 233, 177, 133, 232 };

        /// <summary>
        /// Encrypt plain bytes using AES Crypto Algorithm
        /// </summary>
        /// <param name="plainBytes">Plain input in bytes as target encryption</param>
        /// <param name="password">Password to encrypt</param>
        /// <returns>Encrypted plain bytes (cipher bytes). Returns null if failed</returns>
        /// <exception cref="ArgumentNullException">plainBytes param cannot be null</exception>
        /// <exception cref="ArgumentNullException">password param cannot be null</exception>
        public static byte[] Encrypt(byte[] plainBytes, string password)
        {
            if (plainBytes == null)
                throw new ArgumentNullException(nameof(plainBytes), "method: Encrypt; input cannot be null!");
            if (String.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password), "method: Encrypt; password cannot be null!");
            byte[] result = null;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                try
                {
                    aes.Key = CreatePassword(password);
                    aes.IV = _iv;
                    using (ICryptoTransform crypto = aes.CreateEncryptor())
                    {
                        result = crypto.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    }
                }
                catch { result = null; }
            }
            return result;
        }
        /// <summary>
        /// Decrypt cipher bytes using AES Crypto Algorithm
        /// </summary>
        /// <param name="cipherBytes">Cipher bytes data to decrypt</param>
        /// <param name="password">Password to decrypt</param>
        /// <returns>Decrypted data / Plain bytes. Returns null if failed</returns>
        /// <exception cref="ArgumentNullException">cipherBytes param cannot be null</exception>
        /// <exception cref="ArgumentNullException">password param cannot be null</exception>
        public static byte[] Decrypt(byte[] cipherBytes, string password)
        {
            if (cipherBytes == null)
                throw new ArgumentNullException(nameof(cipherBytes), "method: Decrypt; input cannot be null!");
            if (String.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password), "method: Decrypt; password cannot be null!");
            byte[] result = null;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                try
                {
                    aes.Key = CreatePassword(password);
                    aes.IV = _iv;
                    using (ICryptoTransform crypto = aes.CreateDecryptor())
                    {
                        result = crypto.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                    }
                }
                catch { result = null; }
            }
            return result;
        }

        /// <summary>
        /// Encrypt plain text using AES Crypto Algorithm
        /// </summary>
        /// <param name="plainText">Plain input as target encryption</param>
        /// <param name="password">Password to encrypt</param>
        /// <returns>Ciphertext in base64 string format. Returns null if failed</returns>
        /// <exception cref="ArgumentNullException">plainText param cannot be null</exception>
        /// <exception cref="ArgumentNullException">password param cannot be null</exception>
        public static string Encrypt(string plainText, string password)
        {
            if (String.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText), "method: Encrypt; input cannot be null!");
            if (String.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password), "method: Encrypt; password cannot be null!");
            byte[] resultBytes = Encrypt(GetUTF8Bytes(plainText), password);
            string result = resultBytes == null ? null : Convert.ToBase64String(resultBytes);
            return result;

        }
        /// <summary>
        /// Decrypt base64 string cipher text to plain text
        /// </summary>
        /// <param name="cipherText">Base64 string cipher text</param>
        /// <param name="password">Password to decrypt</param>
        /// <returns>Plain text. Returns null if failed</returns>
        /// <exception cref="ArgumentNullException">cipherText param cannot be null</exception>
        /// <exception cref="ArgumentNullException">password param cannot be null</exception>
        public static string Decrypt(string cipherText, string password)
        {
            if (String.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException(nameof(cipherText), "method: Decrypt; input cannot be null!");
            if (String.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password), "method: Decrypt; password cannot be null!");
            byte[] resultBytes = Decrypt(Convert.FromBase64String(cipherText), password);
            string result = resultBytes == null ? null : GetUTF8String(resultBytes);
            return result;
        }
        #endregion


        #region Hashing
        /// <summary>
        /// Get MD5 hash from input bytes
        /// </summary>
        /// <param name="data">Data in bytes</param>
        /// <returns>Hashed bytes</returns>
        /// <exception cref="ArgumentNullException">data param cannot be null</exception>
        public static byte[] GetMd5(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "input cannot be null");
            using (MD5 md5 = MD5.Create())
            {
                return md5.ComputeHash(data);
            }
        }

        /// <summary>
        /// Get MD5 hash from input string
        /// </summary>
        /// <param name="text">Normal string</param>
        /// <returns>UTF-8 hashed bytes</returns>
        /// <exception cref="ArgumentNullException">text param cannot be null</exception>
        public static byte[] GetMd5(string text)
        {
            if (String.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "input cannot be null");
            return GetMd5(GetUTF8Bytes(text));
        }

        /// <summary>
        /// Get SHA-1 hash from input bytes
        /// </summary>
        /// <param name="data">Data in bytes</param>
        /// <returns>Hashed bytes</returns>
        /// <exception cref="ArgumentNullException">data param cannot be null</exception>
        public static byte[] GetSha1(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "input cannot be null");
            using (SHA1 sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(data);
            }
        }

        /// <summary>
        /// Get SHA-1 hash from input string
        /// </summary>
        /// <param name="text">Normal string</param>
        /// <returns>UTF-8 hashed bytes</returns>
        /// <exception cref="ArgumentNullException">text param cannot be null</exception>
        public static byte[] GetSha1(string text)
        {
            if (String.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "input cannot be null");
            return GetSha1(GetUTF8Bytes(text));
        }


        /// <summary>
        /// Get SHA-256 hash from input bytes
        /// </summary>
        /// <param name="data">Data in bytes</param>
        /// <returns>Hashed bytes</returns>
        /// <exception cref="ArgumentNullException">data param cannot be null</exception>
        public static byte[] GetSha256(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "input cannot be null");
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }

        /// <summary>
        /// Get SHA-256 hash from input string
        /// </summary>
        /// <param name="text">Normal string</param>
        /// <returns>UTF-8 hashed bytes</returns>
        /// <exception cref="ArgumentNullException">text param cannot be null</exception>
        public static byte[] GetSha256(string text)
        {
            if (String.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "input cannot be null");
            return GetSha256(GetUTF8Bytes(text));
        }


        /// <summary>
        /// Get SHA-384 hash from input bytes
        /// </summary>
        /// <param name="data">Data in bytes</param>
        /// <returns>Hashed bytes</returns>
        /// <exception cref="ArgumentNullException">data param cannot be null</exception>
        public static byte[] GetSha384(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "input cannot be null");
            using (SHA384 sha384 = SHA384.Create())
            {
                return sha384.ComputeHash(data);
            }
        }

        /// <summary>
        /// Get SHA-384 hash from input string
        /// </summary>
        /// <param name="text">Normal string</param>
        /// <returns>UTF-8 hashed bytes</returns>
        /// <exception cref="ArgumentNullException">text param cannot be null</exception>
        public static byte[] GetSha384(string text)
        {
            if (String.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "input cannot be null");
            return GetSha384(GetUTF8Bytes(text));
        }


        /// <summary>
        /// Get SHA-512 hash from input bytes
        /// </summary>
        /// <param name="data">Data in bytes</param>
        /// <returns>Hashed bytes</returns>
        /// <exception cref="ArgumentNullException">data param cannot be null</exception>
        public static byte[] GetSha512(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "input cannot be null");
            using (SHA512 sha512 = SHA512.Create())
            {
                return sha512.ComputeHash(data);
            }
        }

        /// <summary>
        /// Get SHA-512 hash from input string
        /// </summary>
        /// <param name="text">Normal string</param>
        /// <returns>UTF-8 hashed bytes</returns>
        /// <exception cref="ArgumentNullException">text param cannot be null</exception>
        public static byte[] GetSha512(string text)
        {
            if (String.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "input cannot be null");
            return GetSha512(GetUTF8Bytes(text));
        }





        /// <summary>
        /// Get MD5 hash from input bytes
        /// </summary>
        /// <param name="data">Data in bytes</param>
        /// <returns>Hashed bytes in base64 encoded string</returns>
        /// <exception cref="ArgumentNullException">data param cannot be null</exception>
        public static string GetMd5ToBase64(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "input cannot be null");
            return Convert.ToBase64String(GetMd5(data));
        }

        /// <summary>
        /// Get MD5 hash from input string
        /// </summary>
        /// <param name="text">Normal string</param>
        /// <returns>UTF-8 hashed bytes in base64 encoded string</returns>
        /// <exception cref="ArgumentNullException">text param cannot be null</exception>
        public static string GetMd5ToBase64(string text)
        {
            if (String.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "input cannot be null");
            return GetMd5ToBase64(GetUTF8Bytes(text));
        }

        /// <summary>
        /// Get SHA-1 hash from input bytes
        /// </summary>
        /// <param name="data">Data in bytes</param>
        /// <returns>Hashed bytes in base64 encoded string</returns>
        /// <exception cref="ArgumentNullException">data param cannot be null</exception>
        public static string GetSha1ToBase64(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "input cannot be null");
            return Convert.ToBase64String(GetSha1(data));
        }

        /// <summary>
        /// Get SHA-1 hash from input string
        /// </summary>
        /// <param name="text">Normal string</param>
        /// <returns>UTF-8 hashed bytes in base64 encoded string</returns>
        /// <exception cref="ArgumentNullException">text param cannot be null</exception>
        public static string GetSha1ToBase64(string text)
        {
            if (String.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "input cannot be null");
            return GetSha1ToBase64(GetUTF8Bytes(text));
        }


        /// <summary>
        /// Get SHA-256 hash from input bytes
        /// </summary>
        /// <param name="data">Data in bytes</param>
        /// <returns>Hashed bytes in base64 encoded string</returns>
        /// <exception cref="ArgumentNullException">data param cannot be null</exception>
        public static string GetSha256ToBase64(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "input cannot be null");
            return Convert.ToBase64String(GetSha256(data));
        }

        /// <summary>
        /// Get SHA-256 hash from input string
        /// </summary>
        /// <param name="text">Normal string</param>
        /// <returns>UTF-8 hashed bytes in base64 encoded string</returns>
        /// <exception cref="ArgumentNullException">text param cannot be null</exception>
        public static string GetSha256ToBase64(string text)
        {
            if (String.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "input cannot be null");
            return GetSha256ToBase64(GetUTF8Bytes(text));
        }


        /// <summary>
        /// Get SHA-384 hash from input bytes
        /// </summary>
        /// <param name="data">Data in bytes</param>
        /// <returns>Hashed bytes in base64 encoded string</returns>
        /// <exception cref="ArgumentNullException">data param cannot be null</exception>
        public static string GetSha384ToBase64(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "input cannot be null");
            return Convert.ToBase64String(GetSha384(data));
        }

        /// <summary>
        /// Get SHA-384 hash from input string
        /// </summary>
        /// <param name="text">Normal string</param>
        /// <returns>UTF-8 hashed bytes in base64 string</returns>
        /// <exception cref="ArgumentNullException">text param cannot be null</exception>
        public static string GetSha384ToBase64(string text)
        {
            if (String.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "input cannot be null");
            return GetSha384ToBase64(GetUTF8Bytes(text));
        }


        /// <summary>
        /// Get SHA-512 hash from input bytes
        /// </summary>
        /// <param name="data">Data in bytes</param>
        /// <returns>Hashed bytes in base64 encoded string</returns>
        /// <exception cref="ArgumentNullException">data param cannot be null</exception>
        public static string GetSha512ToBase64(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "input cannot be null");
            return Convert.ToBase64String(GetSha512(data));
        }

        /// <summary>
        /// Get SHA-512 hash from input string
        /// </summary>
        /// <param name="text">Normal string</param>
        /// <returns>UTF-8 hashed bytes in base64 encoded string</returns>
        /// <exception cref="ArgumentNullException">text param cannot be null</exception>
        public static string GetSha512ToBase64(string text)
        {
            if (String.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text), "input cannot be null");
            return GetSha512ToBase64(GetUTF8Bytes(text));
        }
        #endregion


        #region Private Methods 
        /// <summary>
        /// Convert string to UTF8 bytes
        /// </summary>
        /// <param name="input">String to convert</param>
        /// <returns>Utf-8 bytes</returns>
        private static byte[] GetUTF8Bytes(string input)
        {
            return UTF32Encoding.UTF8.GetBytes(input);
        }
        /// <summary>
        /// Convert utf-8 bytes to string
        /// </summary>
        /// <param name="input">Utf-8 bytes</param>
        /// <returns>Normal string</returns>
        private static string GetUTF8String(byte[] input)
        {
            return UTF32Encoding.UTF8.GetString(input);
        }
        /// <summary>
        /// Generate AES Key from password, salted using password hash 
        /// and iterated using iteration counter
        /// </summary>
        /// <param name="password">Normal string password</param>
        /// <param name="iteration">Iteration counter. Recommended counter is 10,000</param>
        /// <returns>32 Bytes password generated by RFC2898 Derive Bytes</returns>
        private static byte[] CreatePassword(string password, int iteration = 100000)
        {
            using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(password, GetSha256(password), iteration))
            {
                return rfc.GetBytes(32); //size for MAX_AES_KEY
            }
        }

        #endregion
    }
}

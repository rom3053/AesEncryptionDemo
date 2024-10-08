using System.Security.Cryptography;
using System.Text;

namespace AesEncryptionDemo
{
    public class AesEncryptionService
    {
        private readonly byte[] _passwordBytes;
        private readonly byte[] _saltBytes;

        public AesEncryptionService(string password, string salt)
        {
            _passwordBytes = Encoding.UTF8.GetBytes(password);
            _saltBytes = Encoding.UTF8.GetBytes(salt);
        }

        public async Task<string> EncryptString(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(_passwordBytes, _saltBytes, 32768, HashAlgorithmName.SHA256);
            using Aes aes = Aes.Create();

            aes.KeySize = 256;
            aes.Key = rfc2898DeriveBytes.GetBytes(aes.KeySize / 8);
            aes.IV = rfc2898DeriveBytes.GetBytes(aes.BlockSize / 8);
            using MemoryStream memoryStream = new MemoryStream();

            using CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write);

            await cryptoStream.WriteAsync(bytes, 0, bytes.Length);
            await cryptoStream.FlushFinalBlockAsync();

            return Convert.ToBase64String(memoryStream.ToArray());
        }

        public async Task<string> DecryptString(string value)
        {
            byte[] valueBytes = Convert.FromBase64String(value);
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(_passwordBytes, _saltBytes, 32768, HashAlgorithmName.SHA256);
            using Aes aes = Aes.Create();

            aes.KeySize = 256;
            aes.Key = rfc2898DeriveBytes.GetBytes(aes.KeySize / 8);
            aes.IV = rfc2898DeriveBytes.GetBytes(aes.BlockSize / 8);

            using MemoryStream memoryStream = new MemoryStream();
            using CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Write);

            await cryptoStream.WriteAsync(valueBytes, 0, valueBytes.Length);
            await cryptoStream.FlushFinalBlockAsync();

            valueBytes = memoryStream.ToArray();

            return Encoding.UTF8.GetString(valueBytes);
        }
    }
}

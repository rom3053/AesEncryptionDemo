using System.Security.Cryptography;
using System.Text;

namespace AesEncryptionDemo
{
    public class AesCbcCiphertext
    {
        public byte[] Iv { get; }
        public byte[] CiphertextBytes { get; }

        public static AesCbcCiphertext FromBase64String(string data)
        {
            var dataBytes = Convert.FromBase64String(data);
            return new AesCbcCiphertext(
                dataBytes.Take(16).ToArray(),
                dataBytes.Skip(16).ToArray()
            );
        }

        public AesCbcCiphertext(byte[] iv, byte[] ciphertextBytes)
        {
            Iv = iv;
            CiphertextBytes = ciphertextBytes;
        }

        public override string ToString()
        {
            return Convert.ToBase64String(Iv.Concat(CiphertextBytes).ToArray());
        }
    }

    public class AesEncryptionRandomIVService
    {
        private readonly byte[] _passwordBytes;
        private readonly byte[] _saltBytes;

        public AesEncryptionRandomIVService(string password, string salt)
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
            aes.BlockSize = 128;
            aes.Key = rfc2898DeriveBytes.GetBytes(aes.KeySize / 8);
            using MemoryStream memoryStream = new MemoryStream();

            using CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write);

            await cryptoStream.WriteAsync(bytes, 0, bytes.Length);
            await cryptoStream.FlushFinalBlockAsync();

            var cyphertextBytes = memoryStream.ToArray();

            var result = new AesCbcCiphertext(aes.IV, cyphertextBytes).ToString();
            return result;
        }

        public async Task<string> DecryptString(string value)
        {
            var cbcCiphertext = AesCbcCiphertext.FromBase64String(value);
            var valueBytes = cbcCiphertext.CiphertextBytes;

            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(_passwordBytes, _saltBytes, 32768, HashAlgorithmName.SHA256);
            using Aes aes = Aes.Create();

            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Key = rfc2898DeriveBytes.GetBytes(aes.KeySize / 8);

            using MemoryStream memoryStream = new MemoryStream();
            using CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(aes.Key, cbcCiphertext.Iv), CryptoStreamMode.Write);

            await cryptoStream.WriteAsync(valueBytes, 0, valueBytes.Length);
            await cryptoStream.FlushFinalBlockAsync();

            valueBytes = memoryStream.ToArray();

            return Encoding.UTF8.GetString(valueBytes);
        }
    }
}

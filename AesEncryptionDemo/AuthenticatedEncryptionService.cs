using System.Security.Cryptography;
using System.Text;

namespace AesEncryptionDemo
{
    public class AesGcmCiphertext
    {
        public byte[] Nonce { get; }
        public byte[] Tag { get; }
        public byte[] CiphertextBytes { get; }

        public static AesGcmCiphertext FromBase64String(string data)
        {
            var dataBytes = Convert.FromBase64String(data);
            return new AesGcmCiphertext(
                dataBytes.Take(AesGcm.NonceByteSizes.MaxSize).ToArray(),
                dataBytes[^AesGcm.TagByteSizes.MaxSize..],
                dataBytes[AesGcm.NonceByteSizes.MaxSize..^AesGcm.TagByteSizes.MaxSize]
            );
        }

        public AesGcmCiphertext(byte[] nonce, byte[] tag, byte[] ciphertextBytes)
        {
            Nonce = nonce;
            Tag = tag;
            CiphertextBytes = ciphertextBytes;
        }

        public override string ToString()
        {
            return Convert.ToBase64String(Nonce.Concat(CiphertextBytes).Concat(Tag).ToArray());
        }
    }

    public class AuthenticatedEncryptionService
    {
        private readonly byte[] _saltBytes;
        private readonly byte[] _passwordBytes;

        public AuthenticatedEncryptionService(string password, string salt)
        {
            _passwordBytes = Encoding.UTF8.GetBytes(password);
            _saltBytes = Encoding.UTF8.GetBytes(salt);
        }

        public string Encrypt(string plaintext)
        {
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(_passwordBytes, _saltBytes, 32768, HashAlgorithmName.SHA256);
            var keySize = 256;
            var key = rfc2898DeriveBytes.GetBytes(keySize / 8);
            using var aes = new AesCcm(key);

            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            RandomNumberGenerator.Fill(nonce);
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var ciphertextBytes = new byte[plaintextBytes.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];

            aes.Encrypt(nonce, plaintextBytes, ciphertextBytes, tag);
            return new AesGcmCiphertext(nonce, tag, ciphertextBytes).ToString();
        }

        public string Decrypt(string ciphertext)
        {
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(_passwordBytes, _saltBytes, 32768, HashAlgorithmName.SHA256);
            var keySize = 256;
            var key = rfc2898DeriveBytes.GetBytes(keySize / 8);

            var gcmCiphertext = AesGcmCiphertext.FromBase64String(ciphertext);

            using var aes = new AesCcm(key);

            var plaintextBytes = new byte[gcmCiphertext.CiphertextBytes.Length];

            aes.Decrypt(gcmCiphertext.Nonce, gcmCiphertext.CiphertextBytes, gcmCiphertext.Tag, plaintextBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }
    }
}

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Kusumi512.Tests
{
    /// <summary>
    /// Tests for the Kusumi512Poly1305 AEAD cipher.
    /// </summary>
    public class Kusumi512Poly1305CipherTests
    {
        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static byte[] MakeKey() => new byte[64];
        private static byte[] MakeNonce() => new byte[12];

        private static byte[] MakeDistinctKey()
        {
            var k = new byte[64];
            for (int i = 0; i < k.Length; i++) k[i] = (byte)(i + 1);
            return k;
        }

        private static byte[] MakeDistinctNonce()
        {
            var n = new byte[12];
            for (int i = 0; i < n.Length; i++) n[i] = (byte)(i + 0x10);
            return n;
        }

        private const int TagLength = 16;

        // ---------------------------------------------------------------------------
        // A. Construction + Metadata
        // ---------------------------------------------------------------------------

        [Fact]
        public void Kusumi512Poly1305_Constructor_Succeeds()
        {
            var cipher = new Kusumi512Poly1305(MakeKey(), MakeNonce());
            cipher.Dispose();
        }

        [Fact]
        public void Kusumi512Poly1305_AlgorithmName_IsExpected()
        {
            using var cipher = new Kusumi512Poly1305(MakeKey(), MakeNonce());
            Assert.Equal("Kusumi512-Poly1305", cipher.AlgorithmName);
        }

        // ---------------------------------------------------------------------------
        // B. Input Validation (Constructor)
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(0)]
        [InlineData(32)]
        [InlineData(63)]
        [InlineData(65)]
        [InlineData(128)]
        public void Kusumi512Poly1305_InvalidKeyLength_Throws(int keyLength)
        {
            Assert.Throws<ArgumentException>(() =>
                new Kusumi512Poly1305(new byte[keyLength], MakeNonce()));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(11)]
        [InlineData(13)]
        [InlineData(24)]
        public void Kusumi512Poly1305_InvalidNonceLength_Throws(int nonceLength)
        {
            Assert.Throws<ArgumentException>(() =>
                new Kusumi512Poly1305(MakeKey(), new byte[nonceLength]));
        }

        // ---------------------------------------------------------------------------
        // C/H. Buffer APIs — Sync
        // ---------------------------------------------------------------------------

        [Fact]
        public void Kusumi512Poly1305_Sync_EncryptDecrypt_SmallPlaintext_RoundTrips()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Authenticated PQC!");
            using var cipher = new Kusumi512Poly1305(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = cipher.Encrypt(plaintext);
            byte[] decrypted = cipher.Decrypt(ciphertext);
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Kusumi512Poly1305_Sync_EncryptDecrypt_LargePlaintext_RoundTrips()
        {
            byte[] plaintext = RandomNumberGenerator.GetBytes(4096 + 7);
            using var cipher = new Kusumi512Poly1305(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = cipher.Encrypt(plaintext);
            byte[] decrypted = cipher.Decrypt(ciphertext);
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Kusumi512Poly1305_Sync_Encrypt_CiphertextDiffersFromPlaintext()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Definitely not the ciphertext.");
            using var cipher = new Kusumi512Poly1305(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = cipher.Encrypt(plaintext);
            // Ciphertext prefix (sans tag) should differ from plaintext
            byte[] ctPrefix = new byte[plaintext.Length];
            Buffer.BlockCopy(ciphertext, 0, ctPrefix, 0, plaintext.Length);
            Assert.NotEqual(plaintext, ctPrefix);
        }

        [Fact]
        public void Kusumi512Poly1305_Sync_Encrypt_CiphertextIsLongerByTagLength()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Tag appended");
            using var cipher = new Kusumi512Poly1305(MakeKey(), MakeNonce());
            byte[] ciphertext = cipher.Encrypt(plaintext);
            Assert.Equal(plaintext.Length + TagLength, ciphertext.Length);
        }

        [Fact]
        public void Kusumi512Poly1305_Sync_Decrypt_TamperedCiphertext_Throws()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Tamper me not");
            using var cipher = new Kusumi512Poly1305(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = cipher.Encrypt(plaintext);

            // Flip a bit in the ciphertext (not in the tag)
            ciphertext[0] ^= 0xFF;

            Assert.Throws<CryptographicException>(() => cipher.Decrypt(ciphertext));
        }

        [Fact]
        public void Kusumi512Poly1305_Sync_Decrypt_TamperedTag_Throws()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Tag integrity check");
            using var cipher = new Kusumi512Poly1305(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = cipher.Encrypt(plaintext);

            // Flip a bit in the tag (last TagLength bytes)
            ciphertext[ciphertext.Length - 1] ^= 0x01;

            Assert.Throws<CryptographicException>(() => cipher.Decrypt(ciphertext));
        }

        [Fact]
        public void Kusumi512Poly1305_Sync_Decrypt_TooShort_Throws()
        {
            using var cipher = new Kusumi512Poly1305(MakeKey(), MakeNonce());
            // A ciphertext shorter than the tag length is invalid
            Assert.Throws<ArgumentException>(() =>
                cipher.Decrypt(new byte[TagLength - 1]));
        }

        // ---------------------------------------------------------------------------
        // Buffer APIs — Async
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Kusumi512Poly1305_Async_EncryptDecrypt_SmallPlaintext_RoundTrips()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Async AEAD test!");
            using var cipher = new Kusumi512Poly1305(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = await cipher.EncryptAsync(plaintext);
            byte[] decrypted = await cipher.DecryptAsync(ciphertext);
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public async Task Kusumi512Poly1305_Async_EncryptDecrypt_LargePlaintext_RoundTrips()
        {
            byte[] plaintext = RandomNumberGenerator.GetBytes(8192);
            using var cipher = new Kusumi512Poly1305(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = await cipher.EncryptAsync(plaintext);
            byte[] decrypted = await cipher.DecryptAsync(ciphertext);
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public async Task Kusumi512Poly1305_Async_Decrypt_TamperedCiphertext_Throws()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Async tamper check");
            using var cipher = new Kusumi512Poly1305(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = await cipher.EncryptAsync(plaintext);
            ciphertext[0] ^= 0xFF;
            await Assert.ThrowsAsync<CryptographicException>(() =>
                cipher.DecryptAsync(ciphertext));
        }

        // ---------------------------------------------------------------------------
        // J. In-Place — Always throws NotSupportedException
        // ---------------------------------------------------------------------------

        [Fact]
        public void Kusumi512Poly1305_EncryptInPlace_ThrowsNotSupported()
        {
            using var cipher = new Kusumi512Poly1305(MakeKey(), MakeNonce());
            byte[] buffer = new byte[16];
            Assert.Throws<NotSupportedException>(() =>
                cipher.EncryptInPlace(buffer.AsSpan()));
        }

        [Fact]
        public void Kusumi512Poly1305_DecryptInPlace_ThrowsNotSupported()
        {
            using var cipher = new Kusumi512Poly1305(MakeKey(), MakeNonce());
            byte[] buffer = new byte[16];
            Assert.Throws<NotSupportedException>(() =>
                cipher.DecryptInPlace(buffer.AsSpan()));
        }

        [Fact]
        public async Task Kusumi512Poly1305_EncryptInPlaceAsync_ThrowsNotSupported()
        {
            using var cipher = new Kusumi512Poly1305(MakeKey(), MakeNonce());
            byte[] buffer = new byte[16];
            await Assert.ThrowsAsync<NotSupportedException>(() =>
                cipher.EncryptInPlaceAsync(new Memory<byte>(buffer)));
        }

        [Fact]
        public async Task Kusumi512Poly1305_DecryptInPlaceAsync_ThrowsNotSupported()
        {
            using var cipher = new Kusumi512Poly1305(MakeKey(), MakeNonce());
            byte[] buffer = new byte[16];
            await Assert.ThrowsAsync<NotSupportedException>(() =>
                cipher.DecryptInPlaceAsync(new Memory<byte>(buffer)));
        }

        // ---------------------------------------------------------------------------
        // K. Stream APIs — Sync
        // ---------------------------------------------------------------------------

        [Fact]
        public void Kusumi512Poly1305_Stream_Sync_RoundTrip()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = RandomNumberGenerator.GetBytes(512);

            using var inputStream = new MemoryStream(plaintext);
            using var encryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512Poly1305((byte[])key.Clone(), (byte[])nonce.Clone()))
                cipher.EncryptStream(inputStream, encryptedStream);

            encryptedStream.Position = 0;
            using var decryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512Poly1305((byte[])key.Clone(), (byte[])nonce.Clone()))
                cipher.DecryptStream(encryptedStream, decryptedStream);

            Assert.Equal(plaintext, decryptedStream.ToArray());
        }

        [Fact]
        public void Kusumi512Poly1305_Stream_Sync_SmallBufferSize_RoundTrip()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = RandomNumberGenerator.GetBytes(200);

            using var inputStream = new MemoryStream(plaintext);
            using var encryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512Poly1305((byte[])key.Clone(), (byte[])nonce.Clone()))
                cipher.EncryptStream(inputStream, encryptedStream, bufferSize: 64);

            encryptedStream.Position = 0;
            using var decryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512Poly1305((byte[])key.Clone(), (byte[])nonce.Clone()))
                cipher.DecryptStream(encryptedStream, decryptedStream, bufferSize: 64);

            Assert.Equal(plaintext, decryptedStream.ToArray());
        }

        [Fact]
        public void Kusumi512Poly1305_Stream_Sync_InvalidBufferSize_Throws()
        {
            using var cipher = new Kusumi512Poly1305(MakeKey(), MakeNonce());
            var ms = new MemoryStream();
            Assert.Throws<ArgumentException>(() =>
                cipher.EncryptStream(ms, ms, bufferSize: -1));
        }

        // ---------------------------------------------------------------------------
        // K. Stream APIs — Async
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Kusumi512Poly1305_Stream_Async_RoundTrip()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = RandomNumberGenerator.GetBytes(1024);

            using var inputStream = new MemoryStream(plaintext);
            using var encryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512Poly1305((byte[])key.Clone(), (byte[])nonce.Clone()))
                await cipher.EncryptStreamAsync(inputStream, encryptedStream);

            encryptedStream.Position = 0;
            using var decryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512Poly1305((byte[])key.Clone(), (byte[])nonce.Clone()))
                await cipher.DecryptStreamAsync(encryptedStream, decryptedStream);

            Assert.Equal(plaintext, decryptedStream.ToArray());
        }

        [Fact]
        public async Task Kusumi512Poly1305_Stream_Async_Cancellation_ThrowsOperationCanceled()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = RandomNumberGenerator.GetBytes(1024);

            using var cts = new CancellationTokenSource();
            cts.Cancel(); // Pre-cancel

            using var inputStream = new MemoryStream(plaintext);
            using var encryptedStream = new MemoryStream();
            using var cipher = new Kusumi512Poly1305((byte[])key.Clone(), (byte[])nonce.Clone());

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                cipher.EncryptStreamAsync(inputStream, encryptedStream, cancellationToken: cts.Token));
        }
    }
}

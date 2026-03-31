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
    /// Tests for the Kusumi512 stream cipher.
    /// </summary>
    public class Kusumi512CipherTests
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

        // ---------------------------------------------------------------------------
        // A. Construction + Metadata
        // ---------------------------------------------------------------------------

        [Fact]
        public void Kusumi512_Constructor_Succeeds()
        {
            var cipher = new Kusumi512(MakeKey(), MakeNonce());
            cipher.Dispose();
        }

        [Fact]
        public void Kusumi512_AlgorithmName_IsExpected()
        {
            using var cipher = new Kusumi512(MakeKey(), MakeNonce());
            Assert.Equal("Kusumi512", cipher.AlgorithmName);
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
        public void Kusumi512_InvalidKeyLength_Throws(int keyLength)
        {
            Assert.Throws<ArgumentException>(() =>
                new Kusumi512(new byte[keyLength], MakeNonce()));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(11)]
        [InlineData(13)]
        [InlineData(24)]
        public void Kusumi512_InvalidNonceLength_Throws(int nonceLength)
        {
            Assert.Throws<ArgumentException>(() =>
                new Kusumi512(MakeKey(), new byte[nonceLength]));
        }

        // ---------------------------------------------------------------------------
        // C. Buffer APIs — Sync
        // ---------------------------------------------------------------------------

        [Fact]
        public void Kusumi512_Sync_EncryptDecrypt_SmallPlaintext_RoundTrips()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Hello, PQC!");
            using var cipher = new Kusumi512(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = cipher.Encrypt(plaintext);
            byte[] decrypted = cipher.Decrypt(ciphertext);
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Kusumi512_Sync_EncryptDecrypt_LargePlaintext_RoundTrips()
        {
            byte[] plaintext = RandomNumberGenerator.GetBytes(4096 + 13); // > 4096 bytes
            using var cipher = new Kusumi512(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = cipher.Encrypt(plaintext);
            byte[] decrypted = cipher.Decrypt(ciphertext);
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Kusumi512_Sync_Encrypt_CiphertextDiffersFromPlaintext()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Not all zeroes, definitely.");
            using var cipher = new Kusumi512(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = cipher.Encrypt(plaintext);
            Assert.NotEqual(plaintext, ciphertext);
        }

        [Fact]
        public void Kusumi512_Sync_Encrypt_EmptyPlaintext_ReturnsEmpty()
        {
            using var cipher = new Kusumi512(MakeKey(), MakeNonce());
            byte[] result = cipher.Encrypt(Array.Empty<byte>());
            Assert.Empty(result);
        }

        // ---------------------------------------------------------------------------
        // C. Buffer APIs — Async
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Kusumi512_Async_EncryptDecrypt_SmallPlaintext_RoundTrips()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("Async PQC test!");
            using var cipher = new Kusumi512(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = await cipher.EncryptAsync(plaintext);
            byte[] decrypted = await cipher.DecryptAsync(ciphertext);
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public async Task Kusumi512_Async_EncryptDecrypt_LargePlaintext_RoundTrips()
        {
            byte[] plaintext = RandomNumberGenerator.GetBytes(8192);
            using var cipher = new Kusumi512(MakeDistinctKey(), MakeDistinctNonce());
            byte[] ciphertext = await cipher.EncryptAsync(plaintext);
            byte[] decrypted = await cipher.DecryptAsync(ciphertext);
            Assert.Equal(plaintext, decrypted);
        }

        // ---------------------------------------------------------------------------
        // D. Determinism — Two Fresh Instances Produce Identical Ciphertext
        // ---------------------------------------------------------------------------

        [Fact]
        public void Kusumi512_Determinism_SameKeyNoncePlaintext_SameCiphertext()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = Encoding.UTF8.GetBytes("Determinism check");

            byte[] ct1;
            using (var c1 = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                ct1 = c1.Encrypt(plaintext);

            byte[] ct2;
            using (var c2 = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                ct2 = c2.Encrypt(plaintext);

            Assert.Equal(ct1, ct2);
        }

        // ---------------------------------------------------------------------------
        // E. In-Place APIs — Sync
        // ---------------------------------------------------------------------------

        [Fact]
        public void Kusumi512_InPlace_Sync_RoundTrip()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] original = Encoding.UTF8.GetBytes("In-place round-trip test");
            byte[] buffer = (byte[])original.Clone();

            using (var encCipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                encCipher.EncryptInPlace(buffer);

            Assert.NotEqual(original, buffer); // Encrypted buffer differs

            using (var decCipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                decCipher.DecryptInPlace(buffer);

            Assert.Equal(original, buffer);
        }

        [Fact]
        public void Kusumi512_InPlace_Sync_EmptySpan_Throws()
        {
            using var cipher = new Kusumi512(MakeKey(), MakeNonce());
            Assert.Throws<ArgumentNullException>(() => cipher.EncryptInPlace(Span<byte>.Empty));
        }

        // ---------------------------------------------------------------------------
        // E. In-Place APIs — Async
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Kusumi512_InPlace_Async_RoundTrip()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] original = Encoding.UTF8.GetBytes("Async in-place round-trip");
            byte[] buffer = (byte[])original.Clone();
            var memory = new Memory<byte>(buffer);

            using (var encCipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                await encCipher.EncryptInPlaceAsync(memory);

            Assert.NotEqual(original, buffer);

            using (var decCipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                await decCipher.DecryptInPlaceAsync(memory);

            Assert.Equal(original, buffer);
        }

        // ---------------------------------------------------------------------------
        // F. Stream APIs — Sync
        // ---------------------------------------------------------------------------

        [Fact]
        public void Kusumi512_Stream_Sync_RoundTrip_DefaultBufferSize()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = RandomNumberGenerator.GetBytes(512);

            using var inputStream = new MemoryStream(plaintext);
            using var encryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                cipher.EncryptStream(inputStream, encryptedStream);

            encryptedStream.Position = 0;
            using var decryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                cipher.DecryptStream(encryptedStream, decryptedStream);

            Assert.Equal(plaintext, decryptedStream.ToArray());
        }

        [Fact]
        public void Kusumi512_Stream_Sync_RoundTrip_SmallBufferSize()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = RandomNumberGenerator.GetBytes(300);

            using var inputStream = new MemoryStream(plaintext);
            using var encryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                cipher.EncryptStream(inputStream, encryptedStream, bufferSize: 64);

            encryptedStream.Position = 0;
            using var decryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                cipher.DecryptStream(encryptedStream, decryptedStream, bufferSize: 64);

            Assert.Equal(plaintext, decryptedStream.ToArray());
        }

        [Fact]
        public void Kusumi512_Stream_Sync_InvalidBufferSize_Throws()
        {
            using var cipher = new Kusumi512(MakeKey(), MakeNonce());
            var ms = new MemoryStream();
            Assert.Throws<ArgumentException>(() =>
                cipher.EncryptStream(ms, ms, bufferSize: 0));
        }

        // ---------------------------------------------------------------------------
        // F. Stream APIs — Async (progress + cancellation)
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Kusumi512_Stream_Async_RoundTrip()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = RandomNumberGenerator.GetBytes(1024);

            using var inputStream = new MemoryStream(plaintext);
            using var encryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                await cipher.EncryptStreamAsync(inputStream, encryptedStream);

            encryptedStream.Position = 0;
            using var decryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                await cipher.DecryptStreamAsync(encryptedStream, decryptedStream);

            Assert.Equal(plaintext, decryptedStream.ToArray());
        }

        [Fact]
        public async Task Kusumi512_Stream_Async_Progress_ReportedAtLeastOnce()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = RandomNumberGenerator.GetBytes(4096);

            int progressCallCount = 0;
            double lastProgress = -1.0;
            var progress = new Progress<double>(p =>
            {
                progressCallCount++;
                lastProgress = p;
            });

            using var inputStream = new MemoryStream(plaintext);
            using var encryptedStream = new MemoryStream();
            using var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone());
            await cipher.EncryptStreamAsync(inputStream, encryptedStream, progress: progress);

            // Allow progress callbacks to fire (they run on the thread-pool)
            await Task.Delay(50);

            Assert.True(progressCallCount > 0, "Progress should be reported at least once.");
            Assert.True(lastProgress > 0.0, "Final progress should be positive.");
        }

        [Fact]
        public async Task Kusumi512_Stream_Async_Cancellation_ThrowsOperationCanceled()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = RandomNumberGenerator.GetBytes(1024);

            using var cts = new CancellationTokenSource();
            cts.Cancel(); // Pre-cancel

            using var inputStream = new MemoryStream(plaintext);
            using var encryptedStream = new MemoryStream();
            using var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone());

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                cipher.EncryptStreamAsync(inputStream, encryptedStream, cancellationToken: cts.Token));
        }

        // ---------------------------------------------------------------------------
        // G. Nonce Generator — Stream APIs
        // ---------------------------------------------------------------------------

        [Fact]
        public void Kusumi512_Stream_Sync_NonceGenerator_RoundTrip()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = RandomNumberGenerator.GetBytes(256);

            Func<long, byte[]> nonceGen = _ => MakeDistinctNonce();

            using var inputStream = new MemoryStream(plaintext);
            using var encryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                cipher.EncryptStream(inputStream, encryptedStream, nonceGenerator: nonceGen);

            encryptedStream.Position = 0;
            using var decryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                cipher.DecryptStream(encryptedStream, decryptedStream, nonceGenerator: nonceGen);

            Assert.Equal(plaintext, decryptedStream.ToArray());
        }

        [Fact]
        public async Task Kusumi512_Stream_Async_NonceGenerator_RoundTrip()
        {
            byte[] key = MakeDistinctKey();
            byte[] nonce = MakeDistinctNonce();
            byte[] plaintext = RandomNumberGenerator.GetBytes(256);

            Func<long, Task<byte[]>> nonceGen = _ => Task.FromResult(MakeDistinctNonce());

            using var inputStream = new MemoryStream(plaintext);
            using var encryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                await cipher.EncryptStreamAsync(inputStream, encryptedStream, nonceGenerator: nonceGen);

            encryptedStream.Position = 0;
            using var decryptedStream = new MemoryStream();
            using (var cipher = new Kusumi512((byte[])key.Clone(), (byte[])nonce.Clone()))
                await cipher.DecryptStreamAsync(encryptedStream, decryptedStream, nonceGenerator: nonceGen);

            Assert.Equal(plaintext, decryptedStream.ToArray());
        }

        // ---------------------------------------------------------------------------
        // H. Known-Answer / Golden Vector
        // ---------------------------------------------------------------------------

        [Fact]
        public void Kusumi512_KnownAnswer_GoldenVector()
        {
            // Stable regression anchor: fixed key, nonce, plaintext → fixed ciphertext.
            // Key: bytes 0x01–0x40; Nonce: bytes 0x10–0x1B
            byte[] key = MakeDistinctKey();    // 1..64
            byte[] nonce = MakeDistinctNonce(); // 0x10..0x1B

            byte[] plaintext = Encoding.UTF8.GetBytes("Hello, Kusumi512!");

            // Expected ciphertext (hex), generated from the reference implementation.
            byte[] expected = Convert.FromHexString("553E45CAFBC78C4B3343F22EA73C425A25");

            using var cipher = new Kusumi512(key, nonce);
            byte[] actual = cipher.Encrypt(plaintext);

            Assert.Equal(expected, actual);
        }
    }
}

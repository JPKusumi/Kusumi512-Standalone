using System;
using System.Linq;
using Xunit;

namespace Kusumi512.Tests
{
    public class SymmetricCipherTests
    {
        private static byte[] MakeKey() => new byte[64];
        private static byte[] MakeNonce() => new byte[12];

        [Fact]
        public void Kusumi512_Dispose_ZerosKeyAndNonce()
        {
            byte[] key = new byte[64];
            byte[] nonce = new byte[12];
            // Use non-zero values so we can verify they are cleared
            for (int i = 0; i < key.Length; i++) key[i] = (byte)(i + 1);
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)(i + 0xAA);

            var cipher = new Kusumi512(key, nonce);
            cipher.Dispose();

            Assert.All(key, b => Assert.Equal(0, b));
            Assert.All(nonce, b => Assert.Equal(0, b));
        }

        [Fact]
        public void Kusumi512_Dispose_DoesNotThrow()
        {
            var cipher = new Kusumi512(MakeKey(), MakeNonce());
            var ex = Record.Exception(() => cipher.Dispose());
            Assert.Null(ex);
        }

        [Fact]
        public void Kusumi512Poly1305_Dispose_ZerosKeyAndNonce()
        {
            byte[] key = new byte[64];
            byte[] nonce = new byte[12];
            for (int i = 0; i < key.Length; i++) key[i] = (byte)(i + 1);
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)(i + 0xBB);

            var cipher = new Kusumi512Poly1305(key, nonce);
            cipher.Dispose();

            Assert.All(key, b => Assert.Equal(0, b));
            Assert.All(nonce, b => Assert.Equal(0, b));
        }

        [Fact]
        public void Kusumi512Poly1305_Dispose_DoesNotThrow()
        {
            var cipher = new Kusumi512Poly1305(MakeKey(), MakeNonce());
            var ex = Record.Exception(() => cipher.Dispose());
            Assert.Null(ex);
        }

        [Fact]
        public void Kusumi512_UsingStatement_DisposesOnExit()
        {
            byte[] key = new byte[64];
            byte[] nonce = new byte[12];
            for (int i = 0; i < key.Length; i++) key[i] = (byte)(i + 1);
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)(i + 0xCC);

            using (var cipher = new Kusumi512(key, nonce))
            {
                // cipher is in scope and functional
            }

            Assert.All(key, b => Assert.Equal(0, b));
            Assert.All(nonce, b => Assert.Equal(0, b));
        }
    }
}

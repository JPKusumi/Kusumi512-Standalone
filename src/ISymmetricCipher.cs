namespace Kusumi512
{ 
    /// <summary>
    /// Interface for cryptographic primitives (base for ciphers and hashes).
    /// </summary>
    public interface ICryptoPrimitive : IDisposable
    {
        string AlgorithmName { get; }
    }
    /// <summary>
    /// Interface for symmetric ciphers.
    /// </summary>
    public interface ISymmetricCipher : ICryptoPrimitive
    {
        Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken cancellationToken = default);
        byte[] Encrypt(byte[] plaintext);
        Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default);
        byte[] Decrypt(byte[] ciphertext);
        Task EncryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default);
        void EncryptInPlace(Span<byte> inputOutput);
        Task DecryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default);
        void DecryptInPlace(Span<byte> inputOutput);
        Task EncryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default);
        void EncryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null);
        Task DecryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default);
        void DecryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null);
    }
}
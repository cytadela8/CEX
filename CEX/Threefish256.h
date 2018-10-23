// The GPL version 3 License (GPLv3)
// Copyright (c) 2018 vtdev.com
// This file is part of the CEX Cryptographic library.
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.
//
// 
// Principal Algorithms:
// This cipher is based on the Threefish256 stream cipher designed by Daniel J. Bernstein:
// Threefish256: <a href="http://www.ecrypt.eu.org/stream/salsa20pf.html"/>.
// 
// Implementation Details:
// Threefish256: An implementation if the Threefish256 implemented as a stream cipher
// Written by John Underhill, September 11, 2018
// Contact: develop@vtdev.com

#ifndef CEX_THREEFISH256_H
#define CEX_THREEFISH256_H

#include "IStreamCipher.h"

NAMESPACE_STREAM

/// <summary>
/// A parallelized and vectorized Threefish-256 72-round stream cipher [TSX256] implementation.
/// <para>Uses an optional authentication mode (HMAC(SHA2) or KMAC set through the constructor) to authenticate the stream.</para>
/// </summary>
/// 
/// <example>
/// <description>Encrypt an array:</description>
/// <code>
/// SymmetricKey k(Key, Nonce);
/// Threefish256 cipher;
/// // set to false to run in sequential mode
/// cipher.IsParallel() = true;
/// // calculated automatically based on cache size, but overridable
/// cipher.ParallelBlockSize() = cipher.ProcessorCount() * 3200;
/// cipher.Initialize(true, k);
/// cipher.Transform(Input, InOffset, Output, OutOffset, Length);
/// </code>
///
/// <description>Encrypt and authenticate an array:</description>
/// <code>
/// SymmetricKey k(Key, Nonce);
/// Threefish256 cipher(StreamAuthenticators::HMACSHA256);
/// // set to false to run in sequential mode
/// cipher.IsParallel() = true;
/// // initialize for encryption
/// cipher.Initialize(true, k);
/// cipher.Transform(Input, InOffset, Output, OutOffset, Length);
/// // copy mac to end of ciphertext array
/// cipher.Finalize(Output, OutOffset + Length, CodeLength);
/// </code>
///
/// <description>Decrypt and authenticate an array:</description>
/// <code>
/// SymmetricKey k(Key, Nonce);
/// Threefish256 cipher(StreamAuthenticators::HMACSHA256);
/// // set parallel to true to run in parallel mode
/// cipher.IsParallel() = true;
/// // initialize for decryption
/// cipher.Initialize(false, k);
/// // decrypt the ciphertext
/// // copy mac to temp for comparison
/// std:vector&lt;byte&gt; mac(cipher.TagSize(), 0);
/// cipher.Finalize(mac, 0, mac.size());
/// // constant time comparison of mac to embedded  code
/// IntUtils::Compare(Input, InOffset + Length, mac, 0, mac.size());
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para></para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The transformation function used by Threefish is not limited by a dependency chain; this mode can be both SIMD pipelined and multi-threaded. \n
/// This is achieved by pre-calculating the counters positional offset over multiple 'chunks' of key-stream, which are then generated independently across threads. \n 
/// The key stream generated by encrypting the counter array(s), is used as a source of random, and XOR'd with the message input to produce the cipher text.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description></description></item>
/// <item><description>The Key size is 32 bytes (256 bits).</description></item>
/// <item><description>This cipher is capable of authentication by setting the constructors StreamAuthenticators enumeration to one of the HMAC or KMAC options.</description></item>
/// <item><description>Use the Finalize(Output, Offset, Length) function to calculate the MAC code; that code can either be appended to the cipher-text on encryption, or used to compare to an existing code in the stream using the decryption mode.</description></item>
/// <item><description>In authenticated mode, the cipher-key generated by SHAKE will be constant even with differing MAC generators; only two cipher-text outputs are possible, authenticated or non-authenticated.</description></item>
/// <item><description>If authentication is enabled, the cipher-key and MAC seed are generated using SHAKE, this will change the cipher-text output.</description></item>
/// <item><description>The nonce size is 16 bytes (128 bits), this value is optional but recommended.</description></item>
/// <item><description>Block size is 32 bytes (256 bits) wide.</description></item>
/// <item><description>The Info string is optional, but can be used to create a tweakable cipher; must be no more than 16 bytes in length.</description></item>
/// <item><description>Authentication using HMAC or KMAC, can be invoked by setting the StreamAuthenticators parameter in the constructor.</description></item>
/// <item><description>The authentication code can be generated and added to an encrypted stream using the Finalize(Output, Offset, Length) function.</description></item>
/// <item><description>A MAC code can be verified by calling the boolean Verify(Input, Offset, Length) function.</description></item>
/// <item><description>Permutation rounds are fixed at 96.</description></item>
/// <item><description>Encryption can both be pipelined (AVX2 or AVX512), and multi-threaded with any even number of threads.</description></item>
/// <item><description>The Transform functions are virtual, and can be accessed from an ICipherMode instance.</description></item>
/// <item><description>The transformation methods can not be called until the Initialize(SymmetricKey) function has been called.</description></item>
/// <item><description>If the system supports Parallel processing, and IsParallel() is set to true; passing an input block of ParallelBlockSize() to the transform will be auto parallelized.</description></item>
/// <item><description>The ParallelThreadsMax() property is used as the thread count in the parallel loop; this must be an even number no greater than the number of processer cores on the system.</description></item>
/// <item><description>ParallelBlockSize() is calculated automatically based on processor(s) cache size but can be user defined, but must be evenly divisible by ParallelMinimumSize().</description></item>
/// <item><description>The ParallelBlockSize() can be changed through the ParallelProfile() property</description></item>
/// <item><description>Parallel block calculation ex. <c>ParallelBlockSize = N - (N % .ParallelMinimumSize);</c></description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>The Skein Hash Function Family <a href="https://www.schneier.com/academic/paperfiles/skein1.3.pdf">Skein V1.1</a>.</description></item>
/// <item><description>NIST Round 3 <a href="https://www.schneier.com/academic/paperfiles/skein-1.3-modifications.pdf">Tweak Description</a>.</description></item>
/// <item><description>Skein <a href="https://www.schneier.com/academic/paperfiles/skein-proofs.pdf">Provable Security</a> Support for the Skein Hash Family.</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3 Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition>.</description></item>
/// </list>
/// 
/// </remarks>
class Threefish256 final : public IStreamCipher
{
private:

	static const size_t BLOCK_SIZE = 32;
	static const std::string CLASS_NAME;
	static const size_t INFO_SIZE = 16;
	static const size_t KEY_SIZE = 32;
	static const size_t NONCE_SIZE = 2;
	static const size_t ROUND_COUNT = 72;
	static const size_t STATE_PRECACHED = 2048;
	static const size_t STATE_SIZE = 32;
	static const std::string OMEGA_INFO;

	struct Threefish512State;

	StreamAuthenticators m_authenticatorType;
	std::unique_ptr<Threefish512State> m_cipherState;
	std::vector<byte> m_distributionCode;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	std::vector<size_t> m_legalRounds;
	std::unique_ptr<IMac> m_macAuthenticator;
	ulong m_macCounter;
	std::vector<byte> m_macKey;
	ParallelOptions m_parallelProfile;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	Threefish256(const Threefish256&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	Threefish256& operator=(const Threefish256&) = delete;

	/// <summary>
	/// Initialize the class.
	/// <para>Setting the optional Mac parameter to any value other than None (the default), enables authentication for this cipher.
	/// Use the Finalize function to derive the Mac code once processing of the message stream has completed.</para>
	/// </summary>
	/// 
	/// <param name="Authenticator">The optional Message Authentication Code generator type</param>
	explicit Threefish256(StreamAuthenticators Authenticator = StreamAuthenticators::None);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~Threefish256() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: Unit block size of internal cipher in bytes.
	/// <para>Block size is 64 bytes wide.</para>
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Read Only: The salt value in the initialization parameters (Tau-Sigma).
	/// <para>This value can only be set with the Info parameter of an ISymmetricKey member, or use the default.
	/// Changing this code will create a unique distribution of the cipher.
	/// For best security, the code should be a random extenion of the key, with rounds increased to 40 or more.
	/// Code must be non-zero, 16 bytes in length, and sufficiently asymmetric.
	/// If the Info parameter of an ISymmetricKey is non-zero, it will overwrite the distribution code.</para>
	/// </summary>
	const std::vector<byte> &DistributionCode() override;

	/// <summary>
	/// Read Only: The maximum size of the distribution code in bytes.
	/// <para>The distribution code can be used as a secondary domain key.</para>
	/// </summary>
	const size_t DistributionCodeMax() override;

	/// <summary>
	/// Read Only: The stream ciphers type name
	/// </summary>
	const StreamCiphers Enumeral() override;

	/// <summary>
	/// Read Only: Cipher is ready to transform data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this mode.
	/// If parallel capable, input/output data arrays passed to the transform must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	const bool IsParallel() override;

	/// <summary>
	/// Read Only: Array of allowed cipher input key byte-sizes
	/// </summary>
	const std::vector<SymmetricKeySize> &LegalKeySizes() override;

	/// <summary>
	/// Read Only: Available transformation round assignments
	/// </summary>
	const std::vector<size_t> &LegalRounds() override;

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	const size_t ParallelBlockSize() override;

	/// <summary>
	/// Read/Write: Parallel and SIMD capability flags and recommended sizes.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree() property.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by ParallelMinimumSize().
	/// Changes to these values must be made before the <see cref="Initialize(SymmetricKey)"/> function is called.</para>
	/// </summary>
	ParallelOptions &ParallelProfile() override;

	/// <summary>
	/// Read Only: The stream ciphers class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: Number of rounds
	/// </summary>
	const size_t Rounds() override;

	/// <summary>
	/// Read Only: The legal tag length in bytes
	/// </summary>
	const size_t TagSize() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Calculate the MAC code (Tag) and copy it to the Output array.   
	/// <para>The Finalize call can be made incrementally at any byte interval during the transformation without having to re-initialize the cipher.
	/// The output array must be of sufficient length to receive the MAC code.
	/// This function finalizes the Encryption/Decryption cycle, all data must be processed before this function is called.
	/// Initialize(bool, ISymmetricKey) must be called before the cipher can be re-used.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output array that receives the authentication code</param>
	/// <param name="Offset">Starting offset within the output array</param>
	/// <param name="Length">The number of MAC code bytes to write to the output array.
	/// <para>Must be no greater than the MAC functions output size.</para></param>
	///
	/// <exception cref="Exception::CryptoSymmetricCipherException">Thrown if the cipher was not initialized for authentication</exception>
	void Finalize(std::vector<byte> &Output, const size_t OutOffset, const size_t Length);

	/// <summary>
	/// Initialize the cipher.
	/// <para>If authentication is enabled, setting the Encryption parameter to false will decrypt and authenticate a ciphertext stream.
	/// Authentication on a decrypted stream can be performed using either the boolean Verify(Input, Offset, Length), or manually compared using the Finalize(Output, Offset, Length) function.
	/// If encryption and authentication are set to true, the MAC code can be appended to the ciphertext array using the Finalize(Output, Offset, Length) function.</para>
	/// </summary>
	/// 
	/// <param name="KeyParams">Cipher key structure, containing cipher key, and optional nonce pair and info arrays</param>
	///
	/// <exception cref="Exception::CryptoSymmetricCipherException">Thrown if a null or invalid key is used</exception>
	void Initialize(bool Encryption, ISymmetricKey &KeyParams) override;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	void ParallelMaxDegree(size_t Degree) override;

	/// <summary>
	/// Encrypt/Decrypt one block of bytes
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	void TransformBlock(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Encrypt/Decrypt one block of bytes
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void TransformBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override;

	/// <summary>
	/// Encrypt/Decrypt an array of bytes with offset and length parameters.
	/// <para><see cref="Initialize(SymmetricKey)"/> must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	/// <param name="Length">Number of bytes to process</param>
	void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length) override;

private:

	void Generate(std::array<ulong, 2> &Counter, std::vector<byte> &Output, const size_t OutOffset, const size_t Length);
	void Process(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length);
	void Reset();
};

NAMESPACE_STREAMEND
#endif


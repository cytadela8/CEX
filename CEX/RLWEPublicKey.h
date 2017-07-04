#ifndef _CEX_RLWEPUUBLICKEY_H
#define _CEX_RLWEPUUBLICKEY_H

#include "CexDomain.h"
#include "IAsymmetricKey.h"
#include "RLWEParams.h"

NAMESPACE_ASYMMETRICKEY

using Enumeration::RLWEParams;

/// <summary>
/// A RingLWE Public Key container
/// </summary>
class RLWEPublicKey final : public IAsymmetricKey
{
private:

	bool m_isDestroyed;
	std::vector<byte> m_pCoeffs;
	RLWEParams m_rlweParameters;

public:

	RLWEPublicKey() = delete;
	RLWEPublicKey(const RLWEPublicKey&) = delete;
	RLWEPublicKey& operator=(const RLWEPublicKey&) = delete;
	RLWEPublicKey& operator=(RLWEPublicKey&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The public keys cipher type name
	/// </summary>
	const AsymmetricEngines CipherType() override;

	/// <summary>
	/// Get: The cipher parameters enumeration name
	/// </summary>
	const RLWEParams Parameters();

	/// <summary>
	/// Get: The public keys polynomial
	/// </summary>
	const std::vector<byte> &P();

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="Parameters">The cipher parameter enumeration name</param>
	/// <param name="P">The The public keys polynomial</param>
	RLWEPublicKey(RLWEParams Parameters, std::vector<byte> &P);

	/// <summary>
	/// Initialize this class with a serialized public key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized public key</param>
	RLWEPublicKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~RLWEPublicKey() override;

	//~~~Public Methods~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Serialize a public key to a byte array
	/// </summary>
	std::vector<byte> ToBytes() override;
};

NAMESPACE_ASYMMETRICKEYEND
#endif

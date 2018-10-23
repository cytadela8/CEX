#include "NTRUPrivateKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

NTRUPrivateKey::NTRUPrivateKey(NTRUParams Parameters, std::vector<byte> &R)
	:
	m_isDestroyed(false),
	m_ntruParameters(Parameters),
	m_rCoeffs(R)
{
}

NTRUPrivateKey::NTRUPrivateKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_ntruParameters(NTRUParams::None),
	m_rCoeffs(0)
{
	m_ntruParameters = static_cast<NTRUParams>(KeyStream[0]);
	uint rLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_rCoeffs.resize(rLen);

	for (size_t i = 0; i < rLen; ++i)
	{
		m_rCoeffs[i] = Utility::IntUtils::LeBytesTo16(KeyStream, 5 + (i * sizeof(ushort)));
	}
}

NTRUPrivateKey::~NTRUPrivateKey()
{
	Destroy();
}

//~~~Accessors~~~//

const AsymmetricEngines NTRUPrivateKey::CipherType()
{
	return AsymmetricEngines::NTRU;
}

const AsymmetricKeyTypes NTRUPrivateKey::KeyType()
{
	return AsymmetricKeyTypes::CipherPrivateKey;
}

const NTRUParams NTRUPrivateKey::Parameters()
{
	return m_ntruParameters;
}

const std::vector<byte> &NTRUPrivateKey::R()
{
	return m_rCoeffs;
}

//~~~Public Functions~~~//

void NTRUPrivateKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_ntruParameters = NTRUParams::None;

		if (m_rCoeffs.size() > 0)
		{
			Utility::IntUtils::ClearVector(m_rCoeffs);
		}
	}
}

std::vector<byte> NTRUPrivateKey::ToBytes()
{
	uint rLen = static_cast<uint>(m_rCoeffs.size());
	std::vector<byte> r((rLen * sizeof(ushort)) + 5);
	r[0] = static_cast<byte>(m_ntruParameters);
	Utility::IntUtils::Le32ToBytes(rLen, r, 1);

	for (size_t i = 0; i < rLen; ++i)
	{
		Utility::IntUtils::Le16ToBytes(m_rCoeffs[i], r, 5 + (i * sizeof(ushort)));
	}

	return r;
}

NAMESPACE_ASYMMETRICKEYEND

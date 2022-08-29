#include "GenericTest.h"

#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test{
	using Asymmetric::AsymmetricKey;
	using Asymmetric::AsymmetricKeyPair;

	void GenericTest::RunSgn(IAsymmetricSigner& sgn)
	{
		SigFlip(sgn);
		SigContribution(sgn);
	}

	void GenericTest::SigFlip(IAsymmetricSigner & sgn)
	{
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);;
		std::vector<byte> msgclear(32);
		std::vector<byte> sig(0);
		for (int i = 0; i < 32; i++)
			msg1[i] = i + 2;
		msg1[31] = 0;

		AsymmetricKeyPair* kp = sgn.Generate();

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg1, sig);

		sgn.Initialize(kp->PublicKey());

		// test for sign corresctness
		msg2.clear();
		if (!sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("Signature"), sgn.Name(), std::string("Signature integrity test failed! -DS0"));
		}
		if (msg1 != msg2) {
			throw TestException(std::string("Signature"), sgn.Name(), std::string("Signature integrity test failed! -DS1"));
		}
		ConsoleUtils::WriteLine(sgn.Name() + " verification error out size=" + std::to_string(msg2.size()));

		auto sig_copy = sig;
		for (int v_i = 0; v_i < sig.size(); v_i++) {
			for (int b_i = 0; b_i < 8; b_i++) {
				sig_copy[v_i] = sig[v_i] ^ (1 << b_i);
				msg2.clear();
				if (sgn.Verify(sig_copy, msg2))
				{
					throw TestException(std::string("Signature"), sgn.Name(), 
						std::string("Signature integrity test failed! -DS2 pos=")+std::to_string(v_i)+":"+std::to_string(b_i));
				}
				if (msg2 != msgclear and msg2.size()!=0)
					throw TestException(std::string("Signature"), sgn.Name(),
						std::string("Signature unverficied message leak! -DS2.2 pos=") + std::to_string(v_i) + ":" + std::to_string(b_i));
			}
			sig_copy[v_i] = sig[v_i];
		}
		// test for sign corresctness
		msg2.clear();
		if (!sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("Signature"), sgn.Name(), std::string("Signature integrity test failed! -DS3"));
		}
		if (msg1 != msg2) {
			throw TestException(std::string("Signature"), sgn.Name(), std::string("Signature integrity test failed! -DS4"));
		}

		auto sig_short = sig;
		sig_short.pop_back();
		if (sgn.Verify(sig_short, msg2))
		{
			throw TestException(std::string("Signature"), sgn.Name(), std::string("Signature integrity test failed! -DS5"));
		}

		for (int b = 0; b < 256; b++) {
			auto sig_long = sig;
			sig_long.push_back(b);
			if (sgn.Verify(sig_short, msg2))
			{
				throw TestException(std::string("Signature"), sgn.Name(), std::string("Signature integrity test failed! -DS6 b=") + std::to_string(b));
			}
		}
	}
	void GenericTest::SigContribution(IAsymmetricSigner& sgn)
	{
		std::vector<byte> msg(32);
		std::vector<byte> sig(0);
		std::vector<byte> sigout(0);
		for (int i = 0; i < 32; i++)
			msg[i] = i + 2;
		msg[31] = 0;

		AsymmetricKeyPair* kp = sgn.Generate();

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg, sig);
		sgn.Sign(msg, sigout);
		if (sig != sigout) {
			ConsoleUtils::WriteLine(sgn.Name() + " has non deterministic signature. Skipping msg bit contribution tests - MC1");
			return;
		}
		
		auto msg_copy = msg;
		for (int v_i = 0; v_i < msg.size(); v_i++) {
			for (int b_i = 0; b_i < 8; b_i++) {
				msg_copy[v_i] = msg[v_i] ^ (1 << b_i);
				sigout.clear();
				sgn.Sign(msg_copy, sigout);
				if (sigout == sig)
				{
					throw TestException(std::string("Signature"), sgn.Name(),
						std::string("Message bit contribution test failed! -MC2 pos=") + std::to_string(v_i) + ":" + std::to_string(b_i));
				}
			}
			msg_copy[v_i] = msg[v_i];
		}
		// test for sign corresctness
		if (msg != msg_copy) {
			throw TestException(std::string("Signature"), sgn.Name(),
				std::string("Message bit contribution test failed! -MC3"));
		}

		auto msg_short = msg;
		msg_short.resize(31);
		sigout.clear();
		sgn.Sign(msg_short, sigout);
		if (sig == sigout) {
			throw TestException(std::string("Signature"), sgn.Name(),
				std::string("Message bit contribution test failed! -MC4"));
		}

		for (int b = 0; b < 256; b++) {
			auto msg_long = msg;
			msg_long.resize(33);
			msg_long[32] = b;

			sigout.clear();
			sgn.Sign(msg_long, sigout);
			if (sig == sigout) {
				throw TestException(std::string("Signature"), sgn.Name(),
					std::string("Message bit contribution test failed! -MC5 b=")+std::to_string(b));
			}
		}
	}
}

#ifndef CEXTEST_GENERICTEST_H
#define CEXTEST_GENERICTEST_H

#include "ITest.h"
#include "../CEX/IAsymmetricSigner.h"


namespace Test
{
	using CEX::Asymmetric::Sign::IAsymmetricSigner;

	class GenericTest
	{
	public:
		void RunSgn(IAsymmetricSigner& sgn);
	private:
		void SigFlip(IAsymmetricSigner& sgn);
		void SigContribution(IAsymmetricSigner& sgn);
	};

}
#endif
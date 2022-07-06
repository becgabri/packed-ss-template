/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


#ifndef SCAPI_PRF_H
#define SCAPI_PRF_H
#include "../infra/Common.hpp"
#include "../mid_layer/Mac.hpp"
#include "../cryptoInfra/SecurityLevel.hpp"
#include "math.h"

/**
* Abstract class for pseudorandom function. Every class in this family should derive this class.
* In cryptography, a pseudorandom function family, abbreviated PRF,
* is a collection of efficiently-computable functions which emulate a random oracle in the following way:
* no efficient algorithm can distinguish (with significant advantage) between a function chosen randomly from the PRF family and a random oracle
* (a function whose outputs are fixed completely at random).
*/
class PseudorandomFunction {
public:
	/**
	* Sets the secret key for this prf.
	* The key can be changed at any time.
	*/
	virtual void setKey(SecretKey & secretKey)=0;
	
	/**
	* An object trying to use an instance of prf needs to check if it has already been initialized.
	* @return true if the object was initialized by calling the function setKey.
	*/
	
	virtual bool isKeySet()=0;
	
	virtual string getAlgorithmName()=0;
	
	/**
	* @return the input block size in bytes.
	*/
	virtual int getBlockSize()=0;
	
	/**
	* Generates a secret key to initialize this prf object.
	* @param keyParams algorithmParameterSpec contains the required parameters for the key generation
	* @return the generated secret key
	*/
	virtual SecretKey generateKey(AlgorithmParameterSpec & keyParams)=0;
	
	/**
	* Generates a secret key to initialize this prf object.
	* @param keySize is the required secret key size in bits
	* @return the generated secret key
	*/
	virtual SecretKey generateKey(int keySize)=0;
	
	/**
	* Computes the function using the secret key.
	* The user supplies the input byte vector and the offset from which to take the data from.
	* The user also supplies the output byte vector as well as the offset.
	* The computeBlock function will put the output in the output vector starting at the offset. 
	* This function is suitable for block ciphers where the input/output length is known in advance.
	* @param inBytes input bytes to compute
	* @param inOff input offset in the inBytes array
	* @param outBytes output bytes. The resulted bytes of compute
	* @param outOff output offset in the outBytes array to put the result from
	*/
	virtual void computeBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff)=0;
	
	/**
	* Computes the function using the secret key.
	* This function is provided in the interface especially for the sub-family PrfVaryingIOLength, which may have variable input and output length.
	* If the implemented algorithm is a block cipher then the size of the input as well as the output is known in advance and
	* the use may call the other computeBlock function where length is not require.
	* @param inBytes input bytes to compute
	* @param inOff input offset in the inBytes array
	* @param inLen the length of the input array
	* @param outBytes output bytes. The resulted bytes of compute
	* @param outOff output offset in the outBytes array to put the result from
	* @param outLen the length of the output array
	*/
	virtual void computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen)=0;
	
	/**
	* Computes the function using the secret key.
	* This function is provided in this PseudorandomFunction interface for the sake of interfaces (or classes) for which
	* the input length can be different for each computation. Hmac and Prf/Prp with variable input length are examples of
	* such interfaces.
	*
	* @param inBytes input bytes to compute
	* @param inOffset input offset in the inBytes vector
	* @param inLen the length of the input vector
	* @param outBytes output bytes. The resulted bytes of compute.
	* @param outOffset output offset in the outBytes vector to put the result from
	*/
	virtual void computeBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset)=0;

	/**
	* Factory method. Create concrete instance of the give algorithm name in the default implementation.
	*/
	static std::shared_ptr<PseudorandomFunction> get_new_prf(string algName = "AES");
};

/**
* Abstract class for pseudorandom function with fixed input and output lengths.
* A pseudorandom function with fixed lengths predefined input and output lengths, and there is no need to specify it for each function call.
*/
class PrfFixed : public virtual PseudorandomFunction {};

/**
* Abstract class for pseudorandom permutations which is sub-interface of pseudorandon function. Every prp class should derive this class. 
* Pseudorandom permutations are bijective pseudorandom functions that are efficiently invertible.
* As such, they are of the pseudorandom function type and their input length always equals their output length.
* In addition (and unlike general pseudorandom functions), they are efficiently invertible.
*/
class PseudorandomPermutation : public virtual PseudorandomFunction {
public:
	/**
	* Inverts the permutation using the given key. 
	* This function is a part of the PseudorandomPermutation interface since any PseudorandomPermutation must be efficiently invertible (given the key).
	* For block ciphers, for example, the length is known in advance and so there is no need to specify the length.
	* @param inBytes input bytes to invert.
	* @param inOff input offset in the inBytes array
	* @param outBytes output bytes. The resulted bytes of invert
	* @param outOff output offset in the outBytes array to put the result from
	*/
	virtual void invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff)=0;
	
	/**
	* Inverts the permutation using the given key. 
	* Since PseudorandomPermutation can also have varying input and output length (although the input and the output should be the same length),
	* the common parameter <code>len</code> of the input and the output is needed.
	* @param inBytes input bytes to invert.
	* @param inOff input offset in the inBytes array
	* @param outBytes output bytes. The resulted bytes of invert
	* @param outOff output offset in the outBytes array to put the result from
	* @param len the length of the input and the output
	*/
	virtual void invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len) = 0;
};

/**
* Abstract class for pseudorandom permutation with fixed input and output lengths.
* A pseudorandom permutation with fixed lengths predefined input and output lengths, and there is no need to specify it for each function call.
* Block ciphers, for example, have known lengths and so they implement this interface.
*/
class PrpFixed : public virtual PseudorandomPermutation, public virtual PrfFixed {};

/**
* Marker class. Every class that derives it is signed as AES.
* AES is a blockCipher with fixed input and output lengths and thus implements the interface PrpFixed.
*/
class AES : public PrpFixed {
public:
	virtual ~AES() {}
};

/**
* Marker class. Every class that derives it is signed as TripleDes.
* TripleDes is a blockCipher with fixed input and output lengths and thus implements the interface PrpFixed.
*/
class TripleDES : public virtual PrpFixed {};

/**
* This class implements some common functionality of PrpFixed by having an instance of prfFixed.
*/
class PrpFromPrfFixed : public PrpFixed {
protected:
	shared_ptr<PrfFixed> prfFixed; //The underlying prf.
	virtual ~PrpFromPrfFixed() = 0;
public:
	/**
	* Initialized this PrpFromPrfFixed with a secretKey
	* @param secretKey the secret key
	*/
	void setKey(SecretKey & secretKey) override { prfFixed->setKey(secretKey); };
	bool isKeySet() override { return prfFixed->isKeySet(); };
	
	/**
	* Computes the function using the secret key. 
	*
	* This function is provided in the interface especially for the sub-family PrfVaryingIOLength, which may have variable input and output length.
	* Since this is a prp fixed, both input and output variables are equal and fixed, so this function should not normally be called.
	* If the user still wants to use this function, the specified arguments <code>inLen</code> and <code>outLen</code> should be the same as
	* the result of getBlockSize. otherwise, throws an exception.
	*
	* @param inBytes input bytes to compute
	* @param inOff input offset in the inBytes array
	* @param inLen input array length
	* @param outBytes output bytes. The resulted bytes of compute
	* @param outOff output offset in the outBytes array to put the result from
	* @param outLen output array length
	*/
	virtual void computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff, int outLen) override;
	
	/**
	* Computes the function using the secret key. <p>
	*
	* This function is provided in this PseudorandomFunction interface for the sake of interfaces (or classes) for which
	* the input length can be different for each computation.
	* Since in this case both input and output variables are fixed this function should not normally be called.
	* If the user still wants to use this function, the specified input length should be the same as
	* the result of getBlockSize, otherwise, throws an exception.
	*
	* @param inBytes input bytes to compute
	* @param inOff input offset in the inBytes array
	* @param inLen input array length
	* @param outBytes output bytes. The resulted bytes of compute
	* @param outOff output offset in the outBytes array to put the result from
	*/
	virtual void computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff) override;
	
	/**
	* Inverts the permutation using the given key. <p>
	*
	* This function is suitable for cases where the input/output lengths are varying.
	* Since in this case, both input and output variables are fixed this function should not normally be called.
	* If the user still wants to use this function, the specified argument <code>len</code> should be the same as
	* the result of getBlockSize, otherwise, throws an exception.
	*
	* @param inBytes input bytes to invert
	* @param inOff input offset in the inBytes array
	* @param outBytes output bytes. The resulted bytes of invert.
	* @param outOff output offset in the outBytes array to put the result from
	* @param len the length of the input and the output.
	*/
	virtual void invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len) override;
	using PseudorandomFunction::computeBlock;
	using PseudorandomPermutation::invertBlock;
};

/**
* Abstract class for pseudorandom function with varying input length.
* A pseudorandom function with varying input length does not have predefined input length.
* The input length may be different for each function call, and is determined upon user request.
* The interface PrfVaryingInputLength, groups and provides type safety for every PRF with varying input length.
*/
class PrfVaryingInputLength : public virtual PseudorandomFunction {};

/**
* Abstract class for pseudorandom function with varying input and output lengths.
* A pseudorandom function with varying input/output lengths does not have predefined input and output lengths.
* The input and output length may be different for each compute function call.
* The length of the input as well as the output is determined upon user request.
* The interface PrfVaryingIOLength, groups and provides type safety for every PRF with varying input and output length
*/
class PrfVaryingIOLength : public virtual PseudorandomFunction {};

/**
* Abstract class for pseudorandom permutation with varying input and output lengths.
* A pseudorandom permutation with varying input/output lengths does not have predefined input /output lengths.
* The input and output length (that must be equal) may be different for each function call.
* The length of the input and output is determined upon user request.
* The interface PrpVaryingIOLength, groups and provides type safety for every PRP with varying input/output length.
*/
class PrpVaryingIOLength : public virtual PseudorandomPermutation, public virtual PrfVaryingIOLength {};

/**
* Marker class. Every class that derives it is signed as Hmac.
* Hmac has varying input length and thus implements the interface PrfVaryingInputLength.
*/
class Hmac : public virtual PrfVaryingInputLength, public virtual UniqueTagMac, public virtual UnlimitedTimes {}; 

/**
* This class implements some common functionality of varying input and output length prf classes.
*
* PrfVaryingFromPrfVaryingInput is a pseudorandom function with varying input/output lengths, based on HMAC or any other implementation
* of PrfVaryingInputLength. We take the interpretation that there is essentially a different random function for every output length.
* This can be modeled by applying the random function to the input and the required output length (given as input to the oracle).
* The pseudorandom function must then be indistinguishable from this.
* We use PrfVaryingInputLength for this construction because the input length can already be varying; this makes the construction more simple and efficient.
*/
class PrfVaryingFromPrfVaryingInput : public virtual PrfVaryingIOLength {
protected:
	shared_ptr<PrfVaryingInputLength> prfVaryingInputLength; //the underlying prf varying input
public:
	/**
	* Initializes this PrfVaryingFromPrfVaryingInput with the secret key.
	*/
	void setKey(SecretKey & secretKey) override { prfVaryingInputLength->setKey(secretKey); /*initializes the underlying prf */	};
	
	/**
	* Check that the Secret Key for this instance has been set
	* @return true if key had been set;	false, otherwise.
	*/
	bool isKeySet() { return prfVaryingInputLength->isKeySet(); }
	
	/**
	* Since both input and output variables are varying this function should not be called.
	*/
	void computeBlock(const vector<byte> & inBytes, int inOff, vector<byte> & outBytes, int outOff) override{
		throw runtime_error("Only compute that gets lengths of I/O should be called for Varying Prf");
	}
	
	/**
	* Since both input and output variables are varying this function should not be call.
	*/
	void computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> & outBytes, int outOff) override{
		throw runtime_error("Only compute that gets lengths of I/O should be called for Varying Prf");
	}
	
	/**
	* Generate a SecretKey suitable for a Pseudo random permutation obtained from a Varying Prf.
	* @param keyParams an instance of a class implementing the AlgorithmParameterSpec interface
	* 					that holds the necessary parameters to generate the key.
	* @return the generated secret key
	*/
	SecretKey generateKey(AlgorithmParameterSpec & keyParams) override { return prfVaryingInputLength->generateKey(keyParams); };
	
	/**
	* Generate a SecretKey suitable for a Pseudo random permutation obtained from a Varying Prf.
	* @param keySize bit-length of required Secret Key
	* @return the generated secret key
	*/
	SecretKey generateKey(int keySize) override { return prfVaryingInputLength->generateKey(keySize); };
};

/**
* This class is one implementation of pseudorandom function with varying IO, based on any prf with varying input length. <p>
* The implementation is based on several calls to the underlying Prf and concatenation of the results.
*/
class IteratedPrfVarying : public PrfVaryingFromPrfVaryingInput {
public:
	IteratedPrfVarying() { /* TODO: implement */ };
	
	IteratedPrfVarying(const shared_ptr<PrfVaryingInputLength> & prfVaryingInput) { prfVaryingInputLength = prfVaryingInput; };
	
	string getAlgorithmName() override { return "ITERATED_PRF_VARY_INOUT"; };
	
	int getBlockSize() override { throw runtime_error("prp varying has no fixed block size"); };
	
	/**
	* Computes the iterated permutation. <p>
	*
	* The algorithm pseudocode is:
	*
	* outlen = outBytes.length
	*	x = inBytes
	*	----------------
	*	Let m be the smallest integer for which L*m > outlen, where L is the output length of the PrfVaryingInputLength.
	*	FOR i = 1 to m
	*	compute Yi = PrfVaryingInputLength(k,(x,outlen,i)) [key=k, data=(x,outlen,i)]
	*	return the first outlen bits of Y1,-,Ym
	*
	* This function is necessary since this prf has variable input and output length.
	* @param inBytes - input bytes to compute
	* @param inLen - the length of the input array in bytes
	* @param inOff - input offset in the inBytes array
	* @param outBytes - output bytes. The resulted bytes of compute.
	* @param outOff - output offset in the outBytes array to put the result from
	* @param outLen - the length of the output array in bytes
	*/
	void computeBlock (const vector<byte> & inBytes, int inOff, int inLen, vector<byte> & outBytes, int outOff, int outLen) override;
};

/**
* This class implements some common functionality of PrpVaryingIOLength by having an instance of prfVaryingIOLength.
*/
class PrpFromPrfVarying : public virtual PrpVaryingIOLength {
protected:
	shared_ptr<PrfVaryingIOLength> prfVaryingIOLength; // the underlying prf
public:
	/**
	* Initializes this PrpFromPrfVarying with secret key
	* @param secretKey the secret key
	*/
	void setKey(SecretKey & secretKey) override { prfVaryingIOLength->setKey(secretKey); };
	bool isKeySet() override { return prfVaryingIOLength->isKeySet(); };
	
	/**
	* Computes the function using the secret key.
	*
	* This function is provided in the interface especially for the sub-family PrfFixed, which have fixed input and output length.
	* Since this is a prp varying, this function should not normally be called.
	* If the user still wants to use this function, throws an exception.
	*/
	void computeBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff) override;
	
	/**
	* Computes the function using the secret key.
	*
	* 
	* @param inBytes input bytes to compute
	* @param inOff input offset in the inBytes array
	* @param inLen input array length
	* @param outBytes output bytes. The resulted bytes of compute
	* @param outOff output offset in the outBytes array to put the result from
	* @param outLen output array length
	*/
	void computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff, int outLen) override;

	/**
	* Throws an exception. The other invert block function that gets length should be called.
	*/
	void invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff) override;

	SecretKey generateKey(AlgorithmParameterSpec & keyParams) override { return prfVaryingIOLength->generateKey(keyParams); };
	SecretKey generateKey(int keySize) override { return prfVaryingIOLength->generateKey(keySize); };
	using PseudorandomFunction::computeBlock;
};

/**
* The class LubyRackoffPrpFromPrfVarying is one implementation that has a varying input and output length.
* LubyRackoffPrpFromPrfVarying is a pseudorandom permutation with varying input/output lengths, based on any PRF with a variable input/output length
* (as long as input length = output length). We take the interpretation that there is essentially a different random permutation
* for every input/output length.
*/
class LubyRackoffPrpFromPrfVarying : public virtual PrpFromPrfVarying {
public:
	LubyRackoffPrpFromPrfVarying();
	/**
	* Constructor that accepts a name of a prfVaryingIOLength to be the underlying PRF.
	* @param prfVaryingIOLengthName the underlying PRF name
	*/
	LubyRackoffPrpFromPrfVarying(string prfVaryingIOLengthName);
	LubyRackoffPrpFromPrfVarying(const shared_ptr<PrfVaryingIOLength> & prfVaryingIOLength);

	void computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff) override;
	/**
	* Inverts LubyRackoff permutation using the given key. <p>
	* Since LubyRackoff permutation can also have varying input and output length
	* (although the input and the output should be the same length), the common parameter <code>len</code> of the input and the output is needed.
	* LubyRackoff has a feistel structure and thus invert is possible even though the underlying PRF is not invertible.
	* The pseudocode for inverting such a structure is the following
	* FOR i = 4 to 1
	* SET Ri-1 = Li
	* COMPUTE Li-1 = Ri XOR PRF_VARY_INOUT(k,(Ri-1 (or Li),i),L)
	*                     [key=k, data=(Ri-1,i), outlen = L]
	*	OUTPUT (L0,R0)
	*
	* @param inBytes input bytes to invert.
	* @param inOff input offset in the inBytes array
	* @param outBytes output bytes. The resulted bytes of invert
	* @param outOff output offset in the outBytes array to put the result from
	* @param len the length of the input and the output
	*/
	void invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len) override;
	string getAlgorithmName() override { return "LUBY_RACKOFF_PRP_FROM_PRF_VARYING"; };
	int getBlockSize() override { throw runtime_error("prp varying has no fixed block size"); };
};


#endif
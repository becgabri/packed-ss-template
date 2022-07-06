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


#ifndef SCAPI_KEY_H
#define SCAPI_KEY_H

#include "../infra/Common.hpp"

class Key {
public:
	/*
	* Returns the name of the algorithm associated with this key.
	*/
	virtual string getAlgorithm()=0;
	virtual vector<byte> getEncoded()=0;
	virtual ~Key() {};
};

class SecretKey : Key {
	friend class boost::serialization::access;
private:
	vector<byte> key;
	string algorithm;

public:
	SecretKey() {};
	SecretKey(byte * keyBytes, int keyLen, string algorithm) {
		copy_byte_array_to_byte_vector(keyBytes, keyLen, this->key, 0);
		this->algorithm = algorithm;
	}
	SecretKey(const vector<byte> & key, string algorithm) {
		this->key = key;
		this->algorithm = algorithm;
	};
	string getAlgorithm() override { return algorithm; };
	vector<byte> getEncoded() override { return key; };
	virtual ~SecretKey() {};
	
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & key;
		ar & algorithm;
	}
};

class PublicKey : public Key {};
class PrivateKey : public Key {};
class KeySendableData : public NetworkSerialized {};
class KeySpec {};

class KeyPair {
private:
	PublicKey * publicKey;
	PrivateKey * privateKey;
public:
	KeyPair(PublicKey * pubk, PrivateKey * pvk) {
		publicKey = pubk;
		privateKey = pvk;
	};
	PublicKey * GetPublic() { return publicKey; };
	PrivateKey * GetPrivate() { return privateKey; };
};

class RSAKey {
private:
	biginteger modulus;
public:
	RSAKey(biginteger mod) { modulus = mod; };
	biginteger getModulus() { return modulus; };
};

class RSAPublicKey : public RSAKey, public PublicKey {
private:
	biginteger publicExponent;
public:
	RSAPublicKey(biginteger mod, biginteger pubExp) : RSAKey(mod) { publicExponent = pubExp; };
	biginteger getPublicExponent() { return publicExponent; };
	string getAlgorithm() override { return "RSA"; };
	vector<byte> getEncoded() override { throw NotImplementedException(""); };
};

class RSAPrivateKey : public RSAKey, public PrivateKey {
private:
	biginteger privateExponent;
public:
	RSAPrivateKey(biginteger mod, biginteger privExp) : RSAKey(mod) { privateExponent = privExp; };
	biginteger getPrivateExponent() { return privateExponent; };
	string getAlgorithm() override { return "RSA"; };
	vector<byte> getEncoded() override { throw NotImplementedException(""); };
};

class RSAPrivateCrtKey : public RSAPrivateKey {
public:
	virtual biginteger getPublicExponent() = 0;
	virtual biginteger getPrimeP() = 0;
	virtual biginteger getPrimeQ() = 0;
	virtual biginteger getPrimeExponentP() = 0;
	virtual biginteger getPrimeExponentQ() = 0;
	virtual biginteger getCrtCoefficient() = 0;
};

class AlgorithmParameterSpec {
public: 
	virtual ~AlgorithmParameterSpec(){}
};

class RSAKeyGenParameterSpec : public AlgorithmParameterSpec {};
#endif
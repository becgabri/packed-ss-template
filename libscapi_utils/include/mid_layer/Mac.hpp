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


#ifndef SCAPI_MAC_H
#define SCAPI_MAC_H
#include "../infra/Common.hpp"
#include "../cryptoInfra/Key.hpp"

/**
* Abstract class for Mac. Every class in this family must derive this class.
* In cryptography, a message authentication code (often MAC) is a short piece of information used to authenticate a message.
* A MAC algorithm, accepts as input a secret key and an arbitrary-length message to be authenticated,
* and outputs a tag. The tag value protects both a message's data integrity as well as its authenticity, by allowing verifiers
* (who also possess the secret key) to detect any changes to the message content.
*/
class Mac {
public:
	/**
	* Sets the secret key for this mac.
	* The key can be changed at any time.
	* @param secretKey secret key
	*/
	virtual void setMacKey(SecretKey & secretKey)=0;

	/**
	* An object trying to use an instance of mac needs to check if it has already been initialized.
	* @return true if the object was initialized by calling the function setKey.
	*/
	virtual bool isKeySet()=0;

	/**
	* Returns the name of this mac algorithm.
	*/
	virtual string getAlgorithmName()=0;

	/**
	* Returns the input block size in bytes.
	*/
	virtual int getMacSize()=0;

	/**
	* Generates a secret key to initialize this mac object.
	* @param keyParams algorithmParameterSpec contains  parameters for the key generation of this mac algorithm.
	* @return the generated secret key.
	* @throws InvalidParameterSpecException if the given keyParams does not match this mac algoithm.
	*/
	virtual SecretKey generateKey(AlgorithmParameterSpec & keyParams) = 0 ;

	/**
	* Generates a secret key to initialize this mac object.
	* @param keySize is the required secret key size in bits.
	* @return the generated secret key.
	*/
	virtual SecretKey generateKey(int keySize)=0;

	/**
	* Computes the mac operation on the given msg and return the calculated tag.
	* @param msg the message to operate the mac on.
	* @param offset the offset within the message array to take the bytes from.
	* @param msgLen the length of the message in bytes.
	* @return the return tag from the mac operation.
	*/
	virtual vector<byte> mac(const vector<byte> &msg, int offset, int msgLen) = 0;

	/**
	* Verifies that the given tag is valid for the given message.
	* @param msg the message to compute the mac on to verify the tag.
	* @param offset the offset within the message array to take the bytes from.
	* @param msgLength the length of the message in bytes.
	* @param tag the tag to verify.
	* @return true if the tag is the result of computing mac on the message. false, otherwise.
	*/
	virtual bool verify(const vector<byte> &msg, int offset, int msgLength, vector<byte>& tag)=0;

	/**
	* Adds the byte array to the existing message to mac.
	* @param msg the message to add.
	* @param offset the offset within the message array to take the bytes from.
	* @param msgLen the length of the message in bytes.
	*/
	virtual void update(vector<byte> & msg, int offset, int msgLen) = 0 ;

	/**
	* Completes the mac computation and puts the result tag in the tag array.
	* @param msg the end of the message to mac.
	* @param offset the offset within the message array to take the bytes from.
	* @param msgLength the length of the message in bytes.
	* @param output - the result tag from the mac operation.
	*/
	virtual void doFinal(vector<byte> & msg, int offset, int msgLength, vector<byte> & tag_res) = 0;
};

/**
* Marker class. Each class that implement this interface is marked as unique tag mac.
*/
class UniqueTagMac : public Mac {};

#endif

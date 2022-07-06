//
// Created by meital on 5/30/18.
//

#ifndef SCAPI_OPENSSLMAC_H
#define SCAPI_OPENSSLMAC_H

#include <openssl/evp.h>
#include "Mac.hpp"

class OpenSSLGMAC : public Mac{

private:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX _ctx;
#else
    EVP_CIPHER_CTX *_ctx;
#endif
    bool _isIVToSet = true;
    vector<byte> keyVec;
    bool _isKeySet = false;  // Until setKey is called set to false.
    shared_ptr<PrgFromOpenSSLAES> random; //source of randomness used in key generation
    vector<byte> iv;

public:

    OpenSSLGMAC(const shared_ptr<PrgFromOpenSSLAES> & random);
    ~OpenSSLGMAC();

    /**
	* Sets the secret key for this mac.
	* The key can be changed at any time.
	* @param secretKey secret key
	*/
    void setMacKey(SecretKey & secretKey) override ;

    /**
    * An object trying to use an instance of mac needs to check if it has already been initialized.
    * @return true if the object was initialized by calling the function setKey.
    */
    bool isKeySet() override { return _isKeySet; };

    /**
    * Returns the name of this mac algorithm.
    */
    string getAlgorithmName() override { return "GMac";};

    /**
    * Returns the input block size in bytes.
    */
    int getMacSize() override { return 28; };

    /**
    * Generates a secret key to initialize this mac object.
    * @param keyParams algorithmParameterSpec contains  parameters for the key generation of this mac algorithm.
    * @return the generated secret key.
    * @throws InvalidParameterSpecException if the given keyParams does not match this mac algoithm.
    */
    SecretKey generateKey(AlgorithmParameterSpec & keyParams) override {
        throw NotImplementedException("To generate a key for this GMAC object use the generateKey(int keySize) function");
    };

    /**
    * Generates a secret key to initialize this mac object.
    * @param keySize is the required secret key size in bits.
    * @return the generated secret key.
    */
    SecretKey generateKey(int keySize) override ;



    /**
    * Computes the mac operation on the given msg and return the calculated tag.
    * @param msg the message to operate the mac on.
    * @param offset the offset within the message array to take the bytes from.
    * @param msgLen the length of the message in bytes.
    * @return the return tag from the mac operation.
    */
    vector<byte> mac(const vector<byte> &msg, int offset, int msgLen) override ;

    /**
    * Verifies that the given tag is valid for the given message.
    * @param msg the message to compute the mac on to verify the tag.
    * @param offset the offset within the message array to take the bytes from.
    * @param msgLength the length of the message in bytes.
    * @param tag the tag to verify.
    * @return true if the tag is the result of computing mac on the message. false, otherwise.
    */
    bool verify(const vector<byte> &msg, int offset, int msgLength, vector<byte>& tag) override ;

    /**
    * Adds the byte array to the existing message to mac.
    * @param msg the message to add.
    * @param offset the offset within the message array to take the bytes from.
    * @param msgLen the length of the message in bytes.
    */
    void update(vector<byte> & msg, int offset, int msgLen) override ;

    /**
    * Completes the mac computation and puts the result tag in the tag array.
    * @param msg the end of the message to mac.
    * @param offset the offset within the message array to take the bytes from.
    * @param msgLength the length of the message in bytes.
    * @param output - the result tag from the mac operation.
    */
    void doFinal(vector<byte> & msg, int offset, int msgLength, vector<byte> & tag_res) override ;


};


#endif //SCAPI_OPENSSLMAC_H

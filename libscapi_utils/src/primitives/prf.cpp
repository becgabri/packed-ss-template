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


#include "../../include/primitives/Prf.hpp"

void PrpFromPrfFixed::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff, int outLen) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inOff > (int)inBytes.size()) || (inOff + inLen > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > (int)outBytes.size()) || (outOff + outLen > (int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	// If the input and output length are equal to the blockSize, call the computeBlock that doesn't take length arguments.
	if (inLen == outLen && inLen == getBlockSize())
		computeBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("input and output lengths should be equal to Block size");
}

void PrpFromPrfFixed::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inOff > (int)inBytes.size()) || (inOff + inLen > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > (int)outBytes.size()) || (outOff + getBlockSize() > (int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	// if the input and output length are equal to the blockSize, call the computeBlock that doesn't take length arguments.
	if (inLen == getBlockSize())
		this->computeBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("input and output lengths should be equal to Block size");
}

void PrpFromPrfFixed::invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// Checks that the offset and length are correct 
	if ((inOff > (int)inBytes.size()) || (inOff + len > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > (int)outBytes.size()) || (outOff + len > (int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");
	if (len == getBlockSize()) //the length is correct
		//Call the derived class implementation of invertBlock ignoring len
		invertBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("the length should be the same as block size");

}

void IteratedPrfVarying::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> & outBytes, int outOff, int outLen) {
	if (!isKeySet())
		throw invalid_argument("secret key isn't set");
	
	// Checks that the offset and length are correct 
	if ((inOff > (int)inBytes.size()) || (inOff + inLen >(int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > (int)outBytes.size()) || (outOff + outLen >(int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	int prfLength = prfVaryingInputLength->getBlockSize(); // The output size of the prfVaryingInputLength.
	int rounds = (int) ceil((float)outLen / (float)prfLength);  // The smallest integer for which rounds * prfLength > outlen.
	vector<byte> intermediateOutBytes(prfLength); // Round result
	vector<byte> currentInBytes(inBytes.begin() + inOff, inBytes.begin() + inOff + inLen); 	//Copy the x (inBytes) to the input of the prf in the beginning.
	currentInBytes.push_back((byte)outLen); // Works for len up to 256. Copy the outLen to the input of the prf after the x.

	int bulk_size;
	int start_index;
	for (int i = 1; i <= rounds; i++) {
		currentInBytes.push_back((byte)i); // Works for len up to 256. Copy the i to the input of the prf.
		// operates the computeBlock of the prf to get the round output
		prfVaryingInputLength->computeBlock(currentInBytes, 0, inLen + 2, intermediateOutBytes, 0);
		// copies the round result to the output byte array
		start_index = outOff + (i - 1)*prfLength;
		// in case of the last round - copies only the number of bytes left to match outLen
		bulk_size = (i == rounds) ? outLen - ((i - 1)*prfLength) : prfLength; 
		memcpy(outBytes.data() + start_index, intermediateOutBytes.data(), bulk_size);
	}
}

LubyRackoffPrpFromPrfVarying::LubyRackoffPrpFromPrfVarying(){
	//Create the underlying prf.
	prfVaryingIOLength = make_shared<IteratedPrfVarying>();
}

LubyRackoffPrpFromPrfVarying::LubyRackoffPrpFromPrfVarying(string prfVaryingIOLengthName) {
	throw NotImplementedException("factories still not implemented");
}

LubyRackoffPrpFromPrfVarying::LubyRackoffPrpFromPrfVarying(const shared_ptr<PrfVaryingIOLength> & _prfVaryingIOLength) {
	auto test = dynamic_pointer_cast<LubyRackoffPrpFromPrfVarying>(_prfVaryingIOLength);
	if (test)
		throw invalid_argument("Cannot create a LubyRackoffPrpFromPrfVarying from a LubyRackoffPrpFromPrfVarying object!");
	prfVaryingIOLength = _prfVaryingIOLength;
}

void LubyRackoffPrpFromPrfVarying::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inOff > (int)inBytes.size()) || (inOff + inLen > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > (int)outBytes.size()) || (outOff + inLen > (int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");
	if (inLen % 2 != 0) // checks that the input is of even length.
		throw invalid_argument("Length of input must be even");

	int sideSize = inLen / 2; // L in the pseudo code
	vector<byte> tmpReference;
	vector<byte> leftNext(sideSize);
	vector<byte> rightNext(sideSize+1);//keeps space for the index. Size of L+1.

	// Let left_current be the first half bits of the input
	vector<byte> leftCurrent(inBytes.begin()+inOff, inBytes.begin() + inOff + sideSize);

	//Let right_current be the last half bits of the input
	vector<byte> rightCurrent(inBytes.begin() + inOff + sideSize, inBytes.begin() + inOff + 2 * sideSize);

	for (int i = 1; i <= 4; i++) {
		// Li = Ri-1
		leftNext.insert(rightCurrent.begin(), leftNext.begin(), rightCurrent.begin() + sideSize);

		// Put the index in the last position of Ri-1
		rightCurrent.push_back((byte)i);

		// Do PRF_VARY_INOUT(k,(Ri-1,i),L) of the pseudocode
		// Put the result in the rightNext array. Later we will XOr it with leftCurrent. Note that the result size is not the entire
		// rightNext array. It is one byte less. The remaining byte will contain the index for the next iteration.
		prfVaryingIOLength->computeBlock(rightCurrent, 0, rightCurrent.size(), rightNext, 0, sideSize);

		// Do Ri = Li-1 ^ PRF_VARY_INOUT(k,(Ri-1,i),L)  
		// XOR rightNext (which is the resulting PRF computation by now) with leftCurrent.
		for (int j = 0; j<sideSize; j++)
			rightNext[j] = (byte)(rightNext[j] ^ leftCurrent[j]);


		//Switch between the current and the next for the next round.
		//Note that it is much more readable and straightforward to copy the next arrays into the current arrays.
		//However why copy if we can switch between them and avoid the performance increase by copying. We can not just use assignment 
		//Since both current and next will point to the same memory block and thus changing one will change the other.
		tmpReference = leftCurrent;
		leftCurrent = leftNext;
		leftNext = tmpReference;

		tmpReference = rightCurrent;
		rightCurrent = rightNext;
		rightNext = tmpReference;
	}

	// Copy the result to the out array.
	outBytes.insert(outBytes.begin() + outOff, leftCurrent.begin(), leftCurrent.begin() + (inLen / 2));
	outBytes.insert(outBytes.begin() + outOff+inLen/2, rightCurrent.begin(), rightCurrent.begin() + (inLen / 2));
}

void LubyRackoffPrpFromPrfVarying::invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len){
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inOff > (int)inBytes.size()) || (inOff + len  > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > (int)outBytes.size()) || (outOff + len > (int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");
	if (len % 2 != 0) // Check that the input is of even length.
		throw invalid_argument("Length of input must be even");

	int sideSize = len / 2; // L in the pseudo code
	vector<byte> tmpReference;
	vector<byte> leftCurrent(sideSize);
	vector<byte> rightCurrent(sideSize + 1); //Keep space for the index. Size of L+1.

	// Let leftNext be the first half bits of the input
	vector<byte> leftNext(inBytes.begin() + inOff, inBytes.begin() + inOff + sideSize);
	// Let rightNext be the last half bits of the input
	vector<byte> rightNext(inBytes.begin() + inOff + sideSize, inBytes.begin() + inOff + 2*sideSize);

	for (int i = 4; i >= 1; i--) {
		//Ri-1 = Li
		rightCurrent.insert(rightCurrent.begin(), leftNext.begin(), leftNext.begin() + sideSize);
		rightCurrent.push_back((byte)i);


		// Do PRF_VARY_INOUT(k,(Ri-1,i),L) of the pseudocode
		// Put the result in the leftCurrent array. Later we will XOr it with rightNext. 
		prfVaryingIOLength->computeBlock(rightCurrent, 0, rightCurrent.size(), leftCurrent, 0, sideSize);

		// does Li-1 = Ri ^ PRF_VARY_INOUT(k,(Ri-1,i),L)  
		// XOR leftCurrent (which is the resulting PRF computation by now) with rightNext.
		for (int j = 0; j<sideSize; j++)
			leftCurrent[j] = (byte)(leftCurrent[j] ^ rightNext[j]);

		// Switch between the current and the next for the next round.
		// Note that it is much more readable and straightforward to copy the next arrays into the current arrays.
		// However why copy if we can switch between them and avoid the performance increase by copying. We can not just use assignment 
		// since both current and next will point to the same memory block and thus changing one will change the other.
		tmpReference = leftNext;
		leftNext = leftCurrent;
		leftCurrent = tmpReference;

		tmpReference = rightNext;
		rightNext = rightCurrent;
		rightCurrent = tmpReference;

	}

	// Copy the result to the out array.
	outBytes.insert(outBytes.begin() + outOff, leftNext.begin(), leftNext.begin()+sideSize);
	outBytes.insert(outBytes.begin() + outOff + sideSize, rightNext.begin(), rightNext.begin() + sideSize);
}


void PrpFromPrfVarying::computeBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	throw out_of_range("to use this prp, call the computeBlock function that specifies the block size length");
}

void PrpFromPrfVarying::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte>& outBytes, int outOff, int outLen) {
	if (!isKeySet())
		throw new IllegalStateException("secret key isn't set");
	// Check that the offsets and lengths are correct.
	if ((inOff > (int)inBytes.size()) || (inOff + inLen > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > (int)outBytes.size()) || (outOff + outLen > (int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	//If the input and output lengths are equal, call the computeBlock which takes just one length argument.
	if (inLen == outLen)
		computeBlock(inBytes, inOff, inLen, outBytes, outOff);

	else throw out_of_range("input and output lengths should be equal");
}

void PrpFromPrfVarying::invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	throw out_of_range("to use this prp, call the invertBlock function which specify the block size length");
}
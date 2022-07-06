//
// Created by moriya on 01/10/17.
//

#ifndef LIBSCAPI_MERSENNE_H
#define LIBSCAPI_MERSENNE_H

#include "NTL/ZZ_p.h"
#include "NTL/ZZ.h"
#ifdef __x86_64__
#include <x86intrin.h>
#elif __aarch64__
#include "../infra/sse2neon.h"
#endif
#include <gmp.h>
#include "Prg.hpp"

using namespace std;
using namespace NTL;

template <class FieldType>
class TemplateField {
protected:

    PrgFromOpenSSLAES prg;
    long fieldParam;
    int elementSizeInBytes;
    int elementSizeInBits;
    FieldType* m_ZERO;
    FieldType* m_ONE;
public:


    /**
     * the function create a field by:
     * generate the irreducible polynomial x^8 + x^4 + x^3 + x + 1 to work with
     * init the field with the newly generated polynomial
     */
    TemplateField(long fieldParam);

    /**
     * return the field
     */

    string elementToString(const FieldType &element);
    FieldType stringToElement(const string &str);


    void elementToBytes(unsigned char* output,FieldType &element);

    FieldType bytesToElement(unsigned char* elemenetInBytes);
    void elementVectorToByteVector(vector<FieldType> &elementVector, vector<byte> &byteVector);

    FieldType* GetZero();
    FieldType* GetOne();

    int getElementSizeInBytes(){ return elementSizeInBytes;}
    int getElementSizeInBits(){ return elementSizeInBits;}
    /*
     * The i-th field element. The ordering is arbitrary, *except* that
     * the 0-th field element must be the neutral w.r.t. addition, and the
     * 1-st field element must be the neutral w.r.t. multiplication.
     */
    FieldType GetElement(long b);
    FieldType Random();
    ~TemplateField();

};

template <class FieldType>
string TemplateField<FieldType>::elementToString(const FieldType& element)
{
    ostringstream stream;
    stream << element;
    string str =  stream.str();
    return str;
}


template <class FieldType>
FieldType TemplateField<FieldType>::stringToElement(const string &str) {

    FieldType element;

    istringstream iss(str);
    iss >> element;

    return element;
}



/**
 * A random random field element, uniform distribution
 */
template <class FieldType>
FieldType TemplateField<FieldType>::Random() {
    unsigned long b;
    if(elementSizeInBytes<=4)
        b = prg.getRandom32();
    else
        b = prg.getRandom64()>>(64-elementSizeInBits);

    return GetElement(b);
}

template <class FieldType>
FieldType* TemplateField<FieldType>::GetZero()
{
    return m_ZERO;
}

template <class FieldType>
FieldType* TemplateField<FieldType>::GetOne()
{
    return m_ONE;
}


template <class FieldType>
TemplateField<FieldType>::~TemplateField() {
    delete m_ZERO;
    delete m_ONE;
}



#endif //LIBSCAPI_MERSSENE_H

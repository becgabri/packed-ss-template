
//
// Created by moriya on 02/10/17.
//

#ifndef NLIBSCAPI_MATRIX_H
#define NLIBSCAPI_MATRIX_H

#include <iostream>
#include <NTL/GF2E.h>
#include <NTL/GF2X.h>
#include <NTL/ZZ_p.h>
#include <NTL/GF2XFactoring.h>
#include <iostream>
#include <vector>
#include <array>
#include <libscapi/include/primitives/Mersenne.hpp>


using namespace NTL;

/**
 * A hyper-invertible matrix is a matrix of which every (non-trivial) square sub-matrix is invertible. Given
 * a hyper-invertible matrix M and vectors x and y satisfying y = M x, then given any |x| components of x
 * and y (any mixture is fine!), one can compute all other components of x and y as a linear function from
 * the given components.
 * Such matrices provide very good diversion and concentration properties: Given a vector x with random-ness in some components;
 * then this very same randomness can be observed in any components of y.
 * Similarly, given a vector x with up to k non-zero elements, then either y will have a non-zero element in
 * each subset of k components, or x is the zero-vector.
 * We present a construction of hyper-invertible matrices and a bunch of applications.
 */

using namespace std;
using namespace NTL;

template<typename FieldType>
class NVDM {
private:
    int m_n,m_m;
    FieldType** m_matrix;
    TemplateField<FieldType> *field;
public:
    NVDM(int n, int m, TemplateField<FieldType> *field);
    NVDM() {};
    ~NVDM();
    void InitVDM(std::vector<FieldType> & alpha);
    void Print();
    void MatrixMult(std::vector<FieldType> &vector, std::vector<FieldType> &answer, int length);

    void allocate(int n, int m, TemplateField<FieldType> *field);
};


template<typename FieldType>
NVDM<FieldType>::NVDM(int n, int m, TemplateField<FieldType> *field) {
    this->m_m = m;
    this->m_n = n;
    this->field = field;
    this->m_matrix = new FieldType*[m_n];
    for (int i = 0; i < m_n; i++)
    {
        m_matrix[i] = new FieldType[m_m];
    }
}

template<typename FieldType>
void NVDM<FieldType>::allocate(int n, int m, TemplateField<FieldType> *field) {

    this->m_m = m;
    this->m_n = n;
    this->field = field;
    this->m_matrix = new FieldType*[m_n];
    for (int i = 0; i < m_n; i++)
    {
        m_matrix[i] = new FieldType[m_m];
    }
}

template<typename FieldType>
void NVDM<FieldType>::InitVDM(std::vector<FieldType>& alpha) {
    if (alpha.size() != m_n) {
        throw std::invalid_argument("Can't initialize VDM, alpha not equal to number of rows");
    }

    for (int i = 0; i < m_n; i++) {
        m_matrix[i][0] = *(field->GetOne());
        for (int k = 1; k < m_m; k++) {
            m_matrix[i][k] = m_matrix[i][k - 1] * (alpha[i]);
        }
    }
}

/**
 * the function print the matrix
 */
template<typename FieldType>
void NVDM<FieldType>::Print()
{
    for (int i = 0; i < m_n; i++)
    {
        for(int j = 0; j < m_m; j++)
        {
            cout << (m_matrix[i][j]) << " ";

        }
        cout << " " << '\n';
    }

}

template<typename FieldType>
void NVDM<FieldType>::MatrixMult(std::vector<FieldType> &vector, std::vector<FieldType> &answer, int length)
{
    for(int i = 0; i < m_n; i++)
    {
        // answer[i] = 0
        answer[i] = *(field->GetZero());

        for(int j=0; j < length; j++)
        {
            answer[i] += (m_matrix[i][j] * vector[j]);
        }
    }

}
//
template<typename FieldType>
NVDM<FieldType>::~NVDM() {
    for (int i = 0; i < m_n; i++) {
        delete[] m_matrix[i];
    }
    delete[] m_matrix;
}

#endif //NLIBSCAPI_MATRIX_H


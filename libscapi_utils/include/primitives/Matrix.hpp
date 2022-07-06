//
// Created by moriya on 02/10/17.
//

#ifndef LIBSCAPI_MATRIX_H
#define LIBSCAPI_MATRIX_H

#include <iostream>
#include <NTL/GF2E.h>
#include <NTL/GF2X.h>
#include <NTL/ZZ_p.h>
#include <NTL/GF2XFactoring.h>
#include <NTL/matrix.h>
#include <iostream>
#include <vector>
#include <array>
#include "Mersenne.hpp"



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

template <typename FieldType>
class HIM {
private:
    int m_n,m_m;
    Mat<FieldType> * m_matrix;
    //FieldType** m_matrix;
    TemplateField<FieldType> *field;
public:

    /**
     * This method allocate m-by-n matrix.
     * m rows, n columns.
     */
    HIM(int m, int n, TemplateField<FieldType> *field);

    HIM();

    /**
     * This method is a construction of a hyper-invertible m-by-n matrix M over a finite field F with |F| ≥ 2n.
     * Let α1,...,αn , β1,...,βm denote fixed distinct elements in F according the vectors alpha and beta,
     * and consider the function f:Fn → Fm,
     * mapping (x1,...,xn) to (y1,...,ym) such that the points (β1,y1),...,(βm,ym) lie on the polynomial g(·)
     * of degree n−1 defined by the points (α1,x1),...,(αn,xn).
     * Due to the linearity of Lagrange interpolation, f is linear and can be expressed as a matrix:
     * M = {λi,j} j=1,...n i=1,...,m
     * where λ i,j = {multiplication}k=1,..n (βi−αk)/(αj−αk)
     */
    void InitHIMByVectors(vector<FieldType> &alpha, vector<FieldType> &beta);

    /**
     * This method create vectors alpha and beta,
     * and init the matrix by the method InitHIMByVectors(alpha, beta).
     */
    void InitHIM();

    /**
     * This method print the matrix
     */
    void Print();

    /**
     * matrix/vector multiplication.
     * The result is the answer vector.
     */
    void MatrixMult(std::vector<FieldType> &vector, std::vector<FieldType> &answer);

    void allocate(int m, int n, TemplateField<FieldType> *field);

    virtual ~HIM();
};



template <typename FieldType>
HIM<FieldType>::HIM(){
    this->m_matrix = NULL;
}

template <typename FieldType>
HIM<FieldType>::HIM(int m, int n, TemplateField<FieldType> *field) {
    // m rows, n columns
    this->m_m = m;
    this->m_n = n;
    this->field = field;
    this->m_matrix = new Mat<FieldType>;
    m_matrix->SetDims(m,n);

}

template <typename FieldType>
void HIM<FieldType>::InitHIMByVectors(vector<FieldType> &alpha, vector<FieldType> &beta)
{
    FieldType lambda;
    if (this->m_matrix == NULL) {
       throw std::invalid_argument("HIM has not been initialized, cannot call InitHIMByVectors");
    }
    if (beta.size() != m_m || alpha.size() != m_n) {
       cout << "Output of beta " << beta.size() << " and row size if " << m_m << endl;
       cout << "Output of alpha " << alpha.size() << " and row if " << m_n << endl;
       throw std::invalid_argument("Incorrect arguments to the InitHIMByVectors function");
    }

    int m = beta.size();
    int n = alpha.size();
    for (int i = 0; i < m; i++)
    {
        for (int j = 0; j < n; j++)
        {
            // lambda = 1
            lambda = *(field->GetOne());

            // compute value for matrix[i,j]
            for (int k = 0; k < n; k++)
            {
                if (k == j)
                {
                    continue;
                }

                lambda *= ((beta[i]) - (alpha[k])) / ((alpha[j]) - (alpha[k]));
            }

            // set the matrix
            (*m_matrix)[i][j] = lambda;
        }
    }
    return;
}


template <typename FieldType>
void HIM<FieldType>::allocate(int m, int n, TemplateField<FieldType> *field)
{
    // m rows, n columns
    this->m_m = m;
    this->m_n = n;
    this->field = field;
    this->m_matrix = new Mat<FieldType>;
    m_matrix->SetDims(m,n);
}

template <typename FieldType>
void HIM<FieldType>::InitHIM()
{
    int i;
    vector<FieldType> alpha(m_n);
    vector<FieldType> beta(m_m);

    // check if valid
    if (256 <= m_m+m_n)
    {
        cout << "error";
    }

    // Let alpha_j and beta_i be arbitrary field elements
    for (i = 0; i < m_n; i++)
    {
        alpha[i] = field->GetElement(i);
    }

    for (i = 0; i < m_m; i++)
    {
        beta[i] = field->GetElement(m_n+i);
    }

    InitHIMByVectors(alpha,beta);
}

template <typename FieldType>
void HIM<FieldType>::Print()
{
    for (int i = 0; i < m_m; i++) {
        for (int j = 0; j < m_n; j++) {
            cout << (*m_matrix)[i][j] << " ";
        }

        cout << " " << '\n';
    }

}

template <typename FieldType>
void HIM<FieldType>::MatrixMult(std::vector<FieldType> &vector, std::vector<FieldType> &answer)
{
    FieldType temp1;
    for(int i = 0; i < m_m; i++)
    {
        // answer[i] = 0
        answer[i] = *(field->GetZero());

        for(int j=0; j < m_n; j++)
        {
            temp1 = (*m_matrix)[i][j] * vector[j];
            //answer[i] = answer[i] + temp1;
            answer[i] += temp1;
        }
    }
}

template <typename FieldType>
HIM<FieldType>::~HIM() {
    if (m_matrix != NULL) {
        delete m_matrix;
    }
}

template<typename FieldType>
class VDM {
private:
    int m_n,m_m;
    Mat<FieldType>* m_matrix;
    TemplateField<FieldType> *field;
public:
    VDM(int n, int m, TemplateField<FieldType> *field);
    VDM() {m_matrix = NULL;};
    ~VDM();
    void InitVDM();
    void InitVDM(std::vector<FieldType>& alpha);
    void Print();
    void MatrixMult(std::vector<FieldType> &vector, std::vector<FieldType> &answer, int length);
    void allocate(int n, int m, TemplateField<FieldType> *field);
};


template<typename FieldType>
VDM<FieldType>::VDM(int n, int m, TemplateField<FieldType> *field) {
    this->m_m = m;
    this->m_n = n;
    this->field = field;
    this->m_matrix = new Mat<FieldType>;
    m_matrix->SetDims(n, m);

}

template<typename FieldType>
void VDM<FieldType>::allocate(int n, int m, TemplateField<FieldType> *field) {
    if (m_matrix != NULL) {
       delete m_matrix;
    }
    this->m_m = m;
    this->m_n = n;
    this->field = field;
    this->m_matrix = new Mat<FieldType>;
    m_matrix->SetDims(n,m);
}

template<typename FieldType>
void VDM<FieldType>::InitVDM() {
    vector<FieldType> alpha(m_n);
    for (int i = 0; i < m_n; i++) {
        alpha[i] = field->GetElement(i + 1);
    }

    for (int i = 0; i < m_n; i++) {
        (*m_matrix)[i][0] = *(field->GetOne());
        for (int k = 1; k < m_m; k++) {
            (*m_matrix)[i][k] = (*m_matrix)[i][k - 1] * (alpha[i]);
        }
    }
}

template<typename FieldType>
void VDM<FieldType>::InitVDM(std::vector<FieldType>& alpha) {
    if (alpha.size() != m_n) {
        throw std::invalid_argument("Can't initialize VDM, alpha not equal to number of rows");
    }

    for (int i = 0; i < m_n; i++) {
        (*m_matrix)[i][0] = *(field->GetOne());
        for (int k = 1; k < m_m; k++) {
            (*m_matrix)[i][k] = (*m_matrix)[i][k - 1] * (alpha[i]);
        }
    }

}

/**
 * the function print the matrix
 */
template<typename FieldType>
void VDM<FieldType>::Print()
{
    for (int i = 0; i < m_n; i++)
    {
        for(int j = 0; j < m_m; j++)
        {
            cout << (*m_matrix)[i][j] << " ";

        }
        cout << " " << '\n';
    }

}

template<typename FieldType>
void VDM<FieldType>::MatrixMult(std::vector<FieldType> &vector, std::vector<FieldType> &answer, int length)
{
    for(int i = 0; i < m_n; i++)
    {
        // answer[i] = 0
        answer[i] = *(field->GetZero());

        for(int j=0; j < length; j++)
        {
            answer[i] += ((*m_matrix)[i][j] * vector[j]);
        }
    }

}
//
template<typename FieldType>
VDM<FieldType>::~VDM() {
    if (m_matrix != NULL) {
        delete m_matrix;
    }
}

#endif //LIBSCAPI_MATRIX_H

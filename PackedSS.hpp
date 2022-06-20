// becgabri (06/19/2022)

#ifndef PACKEDSS_H
#define PACKEDSS_H

#include <libscapi/include/primitives/Mersenne.hpp>
#include <libscapi/include/primitives/Matrix.hpp>
#include <libscapi/include/infra/Common.hpp>
#include <iostream>
#include <cmath>
#include <string>
#include <stdexcept>
#include "TemplateField.h"
#include <tuple>
#include <map>

using namespace std;

// FORWARD DECLARATIONS
//template <class FieldType>
//class ProtocolParty;
template <class FieldType>
void printCV(vector<FieldType>& a) {
    for (int i = 0; i < a.size(); i++) {
        cout << a[i] << "x^" << i << " ";
    }
    cout << endl;
}

template <class FieldType>
void printRoots(vector<FieldType>& a) {
    cout << "(";
    for (int i = 0; i < a.size()-1; i++) {
        cout << a[i] << ", ";
    }
    cout << a[a.size()-1] << ")" << endl;
}

class OptimizedPSS {
private:
       vector<ZZ_p> secrets; 
public:
        int l;
        int d;
        int n;
        int nearest_pow; 
        ZZ_p generator; 
        vector<ZZ_p> roots;
        vector<ZZ_p> A_recover;
        vector<ZZ_p> A_share;
        vector<ZZ_p> A_pts_recover;
        vector<ZZ_p> A_pts_share;
        TemplateField<ZZ_p>* fieldType;
        OptimizedPSS(int l, int d, int n, long field_size, TemplateField<ZZ_p>* field);
        vector<ZZ_p> recoverSS(vector<ZZ_p>& samplePoints);
        vector<ZZ_p> secretShareValues();
        vector<ZZ_p> ptToCoeff(vector<ZZ_p>&, int, bool);
        vector<ZZ_p> multiplyRoots(vector<int>& root_pos);
        void setSecrets(vector<ZZ_p>& lsecrets);
	void generateRandomSecrets();
	void generateRandomDupSecret();
	ZZ_p& operator[](int idx);

        void DFT(vector<ZZ_p>& coeffs, int pow_u);
        void DFT(vector<ZZ_p>& coeffs, int pow_u, int beg, int end);
        vector<ZZ_p> PreserveInDFT(vector<ZZ_p>& coeffs, int pow_u);
        void computeN(vector<ZZ_p>& coeffs, int);
        void InvDFT(vector<ZZ_p>& sample_pts, int pow_u, int end);
        void polyMult(vector<ZZ_p>& a, vector<ZZ_p>& b);
        std::pair<vector<ZZ_p>,vector<ZZ_p>> polyDiv(vector<ZZ_p>& a, vector<ZZ_p>& b); // a / b
        void prepareCoeffs(vector<ZZ_p>& coeffs, int pow_u);

private:
        void reverse_add(int& itr,int pow);
        //vector<FieldType> DFT(vector<FieldType>& coeffs);
        //vector<FieldType> InvDFT(vector<FieldType>& sample_pts, vector<int>& coeff_pos);
        vector<ZZ_p> multPolyList(vector<vector<ZZ_p>>& polys);
        //vector<FieldType> polyMult(vector<FieldType>& a, vector<FieldType>& b);
    
};

ZZ_p& OptimizedPSS::operator[](int idx){
	if (idx >= l) {
		throw invalid_argument("Trying to access a secret value outsid of pack range");
	}
	if (idx >= secrets.size()) {
		throw invalid_argument("Secret values not large enough!! Can't call this function :(");
	}
	return secrets[idx];
}

void OptimizedPSS::generateRandomSecrets() {
    for (int i = 0; i < l; i++) {
        secrets.push_back(fieldType->Random());
    }
}

void OptimizedPSS::generateRandomDupSecret() {
    auto same_secret = fieldType->Random();
    for (int i = 0; i < l; i++) {
        secrets.push_back(same_secret);
    }
}

void OptimizedPSS::setSecrets(vector<ZZ_p>& lsecrets){
    if (lsecrets.size() > l) {
        throw std::invalid_argument("Can't pack more secrets than l!");
    }
    secrets = vector<ZZ_p>(lsecrets.begin(), lsecrets.end());
}

vector<ZZ_p> OptimizedPSS::secretShareValues() {
    // pad out points for coefficient reconstr. 
    int num_rest_pts = d+1-secrets.size();
    // sample $ y values
    vector<ZZ_p> defin_pts(secrets.begin(), secrets.end());
    for (int i = 0; i < num_rest_pts; i++) {
        auto rand = fieldType->Random();
        defin_pts.push_back(rand);
    }
    vector<ZZ_p> defin_pts2(defin_pts.begin(), defin_pts.end());
    bool isShare = true;
    vector<ZZ_p> shares(defin_pts.begin()+l, defin_pts.end());
    shares.reserve(n);

    vector<ZZ_p> recov_coeff;
    recov_coeff = ptToCoeff(defin_pts, nearest_pow-1,isShare);
    prepareCoeffs(recov_coeff, nearest_pow);
    DFT(recov_coeff, nearest_pow);
    // need to pick out the right points here :( 
    int rest_of_pts = n-(d+1-l);
    int end = rest_of_pts + d+1 < (1 << nearest_pow-1) ? rest_of_pts : (1 << nearest_pow-1) - (d+1);
    for (int i = 0; i < end; i++) {
        shares.push_back(recov_coeff[2*(d+1+i)]); 
    }
    for (int i = 0; i < (rest_of_pts - end); i++) {
        shares.push_back(recov_coeff[2*i+1]);
    }
    return shares;
}

vector<ZZ_p> OptimizedPSS::ptToCoeff(vector<ZZ_p>& samplePoints,int pow_u, bool is_share) {
    vector<ZZ_p> n_i;
    n_i.reserve(2*(d+1));
    if (samplePoints.size() != d+1) {
        throw std::invalid_argument("You need at least d+1 points to reconstruct!");
    } 
    if (is_share) {
        // no shifting needed here because we are dealing with half the roots of unity
        for (int i = 0; i < d+1; i++) {
            n_i.push_back(move(samplePoints[i]));
            n_i[i] *= A_pts_share[i];
        } 
    } else {
        
        // need points l+1, l+2, l+3... l+d+1. 
        // most of the points will be from roots of unity generated by
        // h = generator^2 but it's possible some may come from generator
        auto end = (l+d+1) < (1 << nearest_pow-1) ? d+1 : (1 << nearest_pow-1)-l;
        n_i.resize(2*(l+end));
        for (int i = 0; i < end; i++) {
            n_i[2*(l+i)] = samplePoints[i] * A_pts_recover[i];
            //n_i.push_back(samplePoints[i] * A_pts_recover[i]);
        } 
        // do those l pts run over the smaller roots of unity?
        for (int i = 0; i < (d+1)-end; i++) {
            n_i[2*i+1] = samplePoints[i+end] * A_pts_recover[i+end];
        } 
    }  
    // the previous steps should have given us the coefficients of the poly N', we eval. at the points r^-j-1 = (r^(j+1))^-1 for j in 0 ... d to get the coefficients of -[P(x)/A(x)]
    computeN(n_i, pow_u);
    if (is_share) {
        polyMult(n_i, A_share);
    } else {
        polyMult(n_i, A_recover);
    }
    
    n_i.erase(n_i.begin()+d+1, n_i.end()); 
    return n_i; 
}

vector<ZZ_p> OptimizedPSS::recoverSS(vector<ZZ_p>& samplePoints) {
    if (samplePoints.size() < d+1) {
        throw std::invalid_argument("Not enough points to recover the secrets!");
    }
    
    vector<ZZ_p> checkPoints;
    int check_num = samplePoints.size() - (d+1);
    if (check_num > 0) {
        for (auto it = samplePoints.begin()+d+1; it != samplePoints.end(); it++) {
            checkPoints.push_back(*it);
        }
        samplePoints.erase(samplePoints.begin()+d+1, samplePoints.end());
    }

    bool isShare = false;
    auto px = ptToCoeff(samplePoints, nearest_pow, isShare);
    prepareCoeffs(px, nearest_pow);
    DFT(px, nearest_pow); // this is probably just easier
    auto end_of_first_check = check_num+l+d+1 < (1 << nearest_pow-1) ? check_num: (1 << nearest_pow-1) - (l+d+1);
    for (int i = 0; i < end_of_first_check; i++) {
        if (px.at(2*(l+d+1+i)) != checkPoints[i]) {
            cout << "Party " << to_string(d+1+i) << " is cheating!" << endl;
            cout << "Recovered point: " << px[2*(l+d+1+i)] << endl;
            cout << "Point provided: " << checkPoints[i]<< endl;
            throw std::invalid_argument("Recovered point is incorrect"); 
        }
    }
    check_num -= (( 1 << nearest_pow-1) - (l+d+1));
    for (int i = 0; i < check_num; i++) {
        if (px[2*i+1] != checkPoints[end_of_first_check+i]) {
            cout << "Party " << to_string(d+1+end_of_first_check+i) << " is cheating!" << endl;
            cout << "Recovered point: " << px[2*i+1] << endl;
            cout << "Point provided: " << checkPoints[end_of_first_check+i]<< endl;
            throw std::invalid_argument("Recovered point is incorrect");
        }
    }
    // keep the first l 
    for (int i = 0; i < l; i++) {
        px[i] = px[2*i];
    }
    px.erase(px.begin()+l, px.end());
    return px;
}

vector<ZZ_p> OptimizedPSS::multPolyList(vector<vector<ZZ_p>>& polys) {
    // divide and conquer 
    if (polys.size() == 1) {
        return polys[0];
    } else if (polys.size() == 2) {
        polyMult(polys[0], polys[1]);
        return polys[0];
    } else if (polys.size() == 0) {
       throw std::invalid_argument("Ah this shouldn't happen!");
    }
    
    int mid_pt = polys.size() / 2;
    // https://www.tutorialspoint.com/getting-a-subvector-from-a-vector-in-cplusplus
    vector<vector<ZZ_p>> rhs(polys.begin(), polys.begin()+mid_pt);
    vector<vector<ZZ_p>> lhs(polys.begin()+mid_pt, polys.end());
    auto rhs_eval = multPolyList(rhs);
    auto lhs_eval = multPolyList(lhs);
    
    polyMult(rhs_eval, lhs_eval);
    return rhs_eval;
}

// a CONTAINS the result of the multiplication
// b *CAN* be used after this step
// i.e a is of form a_0 ... a_2^j, b_0 ... b_2^j 
// the result of this computation is stored in the first argument
void OptimizedPSS::polyMult(vector<ZZ_p>& a, vector<ZZ_p>& b) {
    auto num_pts = a.size()+b.size()-1;
    auto total = (1 << nearest_pow);
    if (total < num_pts) {
        cout << "Number of roots is " << total << ". Number of pts needed is " << num_pts << endl;
        cout << "A polynomial: " << endl;
        printCV(a);
        cout << "B polynomial: " << endl;
        printCV(b); 
        throw std::invalid_argument("polyMult:: polynomials must be 'small enough'");
    }

    // convert a and b to pt. eval form
    prepareCoeffs(a, nearest_pow);
    DFT(a, nearest_pow);
    int save_b = b.size();
    if (b.size() != (1<<nearest_pow)) {
        prepareCoeffs(b, nearest_pow);
    } 
    auto c = PreserveInDFT(b, nearest_pow);
    //TODO: ensure that n > 2*len(a)
    // multiply points
    //vector<ZZ_p> c_pts;
    //c_pts.reserve(total);    
    for (int i = 0; i<total; i++) {
        a[i] = a[i] * c[i]; 
    }
    InvDFT(a, nearest_pow, num_pts);
    b.erase(b.begin()+save_b, b.end());
}

vector<ZZ_p> OptimizedPSS::multiplyRoots(vector<int>& root_pos) {
    vector<vector<ZZ_p>> list_roots(root_pos.size());
    for (int i = 0 ; i < root_pos.size(); i++) {
        list_roots[i].push_back(-roots[root_pos[i]]);
        list_roots[i].push_back(fieldType->GetElement(1));
    }
    auto A = multPolyList(list_roots);
    return A;
}
vector<ZZ_p> generateRoots(ZZ_p & gen, int TOTAL) {
    vector<ZZ_p> roots;
    roots.reserve(1 << TOTAL);
    roots.push_back(power(gen,0));
    cout << 0 << endl;
    for (int i = 1; i < TOTAL+1; i++) {
        // always fix 2^j-i to be 1 
        for (int j = 0; j < (1<< (i-1)); j++) {
            auto elt = 1 << (TOTAL - i); 
            for (int k = 0; k < i-1; k++) {
                auto bit_mask = (j >> k) & 1;
                if (bit_mask == 1) {
                    elt = elt + (1 << (TOTAL-1-k));
                }
            }
            cout << elt << endl;
            roots.push_back(power(gen,elt));
        }
    }
    return roots;
}

OptimizedPSS::OptimizedPSS(int l, int d, int n, long field_size, TemplateField<ZZ_p>* field) : l(l), d(d), n(n) {
    // 3193032821760 = 2^10 * 3^3 * 5 * 19 * 173 * 7027
    if (field_size != 3193032821761) {
        throw std::invalid_argument("You must use this with the hardcoded field Z_p of size 3193032821761");
    }
    fieldType = field;
    nearest_pow = ceil(log2(n+l));
    auto total_num_pts = 1 << nearest_pow;
    roots.reserve(total_num_pts); // the first n+l points are used for the most part in the protocol 
    if (nearest_pow > 10) {
        throw std::invalid_argument("Number of parties and packed ss are too large for the OptimizedPSS field");
    }
    auto pow_for_sub = (field_size - 1) / total_num_pts; 
    generator = power(fieldType->GetElement(14), pow_for_sub); 
    // order the roots in memory in the most efficient way for memory acceses
    // see https://medium.com/snips-ai/optimizing-threshold-secret-sharing-c877901231e5 by Mathieu Poumeyrol
    //we want all roots of unity for nearest_pow-1 first
    auto h = power(generator, 2);
    int half_pts = (1 << nearest_pow-1);
    for (int i = 0; i < half_pts; i++) {
        roots.push_back(power(h, i));
    }
    // fill out with the rest of the points
    for (int i = 0; i < half_pts; i++) {
        roots.push_back(power(generator, 2*i+1));
    }
    if (roots[half_pts-1]*h != roots[0]) {
        cout << "Not a subgroup!" << endl;
    }
    if (power(generator, total_num_pts) != roots[0]) {
        cout << "Not a group!" << endl;
    }
       
    vector<int> shared_roots(d+1-l);
    for (int i = l; i < d+1; i++) {
        shared_roots[i-l] = i;
    }
    vector<ZZ_p> shared_A = multiplyRoots(shared_roots);

    // multiply rest of points used in A_shared?? 
    shared_roots.erase(shared_roots.begin(),shared_roots.end());
    for (int i = 0; i < l; i++) {
        shared_roots.push_back(i);
    }
    A_share = multiplyRoots(shared_roots);

    polyMult(A_share, shared_A);
    vector<int> recover_roots(l);
    for (int i = 0; i<l;i++) {
        recover_roots[i] = d+1+i;    
    }

    A_recover = multiplyRoots(recover_roots);
    // shared_A
    polyMult(A_recover, shared_A);

    // calculate A, A', and eval. pts. A'(x_i) = A_i(x_i)
    //vector<ZZ_p> A_deriv(d+1);
    // calculate A' the easy way
    
    for (int i = 0; i < d+1; i++) {
        A_pts_recover.push_back(A_recover[i+1] * (i+1));
    }
    // calcuate A_i(x_i)
    vector<ZZ_p> A_pts_rec_c(A_pts_recover.begin(), A_pts_recover.end());
    prepareCoeffs(A_pts_rec_c, nearest_pow);
    DFT(A_pts_rec_c, nearest_pow); 
    auto end = l+d+1 < (1 << nearest_pow-1) ? d+1 : ( 1<< nearest_pow-1) - l; 
    for (int i = 0; i < end; i++) {
        A_pts_recover[i] = A_pts_rec_c[2*(l+i)];
    }
    for (int i = 0; i < (d+1) - end; i++) {
        A_pts_recover[end+i] = A_pts_rec_c[2*i+1];
    }
    A_pts_recover.erase(A_pts_recover.begin()+d+1, A_pts_recover.end());
    // repeat for share points
    for (int i = 0; i < d+1; i++) {
        A_pts_share.push_back(A_share[i+1] * (i+1));
    }
    // calcuate A_i(x_i)
    prepareCoeffs(A_pts_share, nearest_pow);
    //DFT(A_pts_share, nearest_pow, 0, d+1); 
    DFT(A_pts_share, nearest_pow); 
    for ( int i = 0; i < d+1; i++) {
        A_pts_share[i] = A_pts_share[2*i];
    }
    A_pts_share.erase(A_pts_share.begin()+d+1, A_pts_share.end());
    // attempting to do *anything* to make this code faster, pre-computing
    // inverse
    for (int i = 0; i < d+1; i++) {
        A_pts_share[i] = inv(A_pts_share[i]);
        A_pts_recover[i] = inv(A_pts_recover[i]); 
    }
    
}

void OptimizedPSS::DFT(vector<ZZ_p>& coeffs, int pow_u, int begin, int end) {
    DFT(coeffs, pow_u); 
    coeffs.erase(coeffs.begin()+end, coeffs.end());
    coeffs.erase(coeffs.begin(), coeffs.begin()+begin);
    return;
}

void OptimizedPSS::computeN(vector<ZZ_p>& coeffs, int pow_u) {
    prepareCoeffs(coeffs, pow_u);
    DFT(coeffs, pow_u);
    // make sure you grab the d+1 points you need
    auto MASK = (1 << pow_u) - 1;
    //for (int it = 0; it < (1 << (nearest_pow-1)); it++) {
    auto need_saved = (d+1) - (1 << (pow_u-1));
    if (need_saved > 0) {
        vector<ZZ_p> save_v(need_saved);
        int need_nothing = (1 << pow_u-1) - need_saved; 
        for (int it = 0; it < need_nothing; it++) {
            auto one_more_inv = ((1 << pow_u) - it - 1) & MASK;
            coeffs[it] = -coeffs[one_more_inv];
        }     
        for (int it = 0; it < need_saved; it++) {
            auto one_more_inv = ((1 << pow_u) - (it+need_nothing) - 1) & MASK;
            save_v[need_saved-1-it] = coeffs[need_nothing+it]; 
            coeffs[need_nothing+it] = -coeffs[one_more_inv];
            
        }
        for (int it = 0; it < need_saved; it++) {
            auto idx = (1 << pow_u-1) + it;
            coeffs[idx] = -save_v[it];
        }
    } else {
        for (int it = 0; it < d+1; it++) {
            auto one_more_inv = ((1 << pow_u) - it - 1) & MASK;
            coeffs[it] = -coeffs[one_more_inv];
        }
    }
    coeffs.erase(coeffs.begin()+d+1, coeffs.end()); 
    return;    
}

// again from Mathieu Poumeyrol
// to undo this ordering, just do it twice  
void OptimizedPSS::prepareCoeffs(vector<ZZ_p>& coeffs, int pow_u) {
    auto zero = fieldType->GetElement(0);
    int total = 1 << pow_u; // 2^j
    coeffs.resize(total, zero);
    /*
    for (int i = 1; i < nearest_pow+1; i++) {
        // always fix 2^j-i to be 1 
        for (int j = 0; j < (1<< (i-1)); j++) {
            auto elt = 1 << (nearest_pow - i); 
            for (int k = 0; k < i-1; k++) {
                auto bit_mask = (j >> k) & 1;
                if (bit_mask == 1) {
                    elt = elt + (1 << (nearest_pow-1-k));
                }
            }
            // do swap 
            auto this_pos = (1 << (i-1)) + j;
            auto save = coeffs[this_pos];
            if (this_pos < elt) {
                coeffs[this_pos] = coeffs[elt];
                coeffs[elt] = save;
            }
        }
    }
    */
    return;
}


// taking the forward iteration loop from Mathieu Poumeyrol
// Assumpt.: the coefficients are *sequentially* ordered
// i.e. input coefficients as a_0 a_1 ... a_2^j-1
// the OUTPUT is ordered as p(0) p(1) ... p(2^j-1) <- I'm just represeneting elements by their exponent here wrt the generator
void OptimizedPSS::DFT(vector<ZZ_p>& coeffs, int pow_u) {
    auto order_gr = (1 << pow_u);
    auto MASK = order_gr - 1;
    ZZ_p gen;
    if (pow_u == nearest_pow) {
        gen = generator;
    } else {
        gen = generator*generator;
    }

    if (pow_u == 0) {
        return;
    }
    else if (pow_u == 1) {
        auto save = coeffs[0];
        coeffs[0] = coeffs[0] + coeffs[1];
        coeffs[1] = save - coeffs[1];
        return;
    }

    // we're starting off not in the correct order for 
    // the coefficients. if we want to deal with this w.o
    // reordering, we'll need to do something special for the 
    // first run through of the loop 
    auto step = (1 << pow_u - 1);
    vector<ZZ_p> scratch_space(1 << pow_u); 
    int base = 0; 
    for (int k = 0; k < step; k++) {
        // k and k+step are the *coefficients* under consider.
        // because coeffs doubles as the evaluation in order w^0 ... w^2^j-1
        // for the roots of unity,we will be forced to overwrite the coefficient of 2k+1
        // and since we will need it (shortly), we MUST save it somewhere
        auto k_d = 2*k;

        scratch_space[k_d] = coeffs[k_d];
        scratch_space[k_d+1] = coeffs[k_d+1];
        if (k_d >= base+step) {
            coeffs[k_d] = scratch_space[base] + scratch_space[base+step];
            coeffs[k_d+1] = scratch_space[base] - scratch_space[base+step];
        } else if (k_d >= base) { 
            // k_d will be less than base+step 
            coeffs[k_d] = scratch_space[base] + coeffs[base+step];
            coeffs[k_d+1] = scratch_space[base] - coeffs[base+step]; 
        } else { // k_d < base, k_d < base + step
            coeffs[k_d] = coeffs[base] + coeffs[base+step];
            coeffs[k_d+1] = coeffs[base] - coeffs[base+step]; 
        }
        reverse_add(base, pow_u); 
        
    } 

    ZZ_p y, factor, stride; 
    for (int i = 1; i < pow_u; i++) {
        auto step = (1 << i); // 2^i
        auto jmp = 2*step; // 2^i+1
        // factor stride 
        stride = power(gen, order_gr >> (i+1)); // 2^(j-i-1)
        factor = fieldType->GetElement(1);
        for (int k = 0; k < step; k++) {
            auto base = k;
            while (base < order_gr) { 
                // pair spots are step apart 
                // j*jmp +k,  +k + step
                y = factor * coeffs[base+step]; 
                // update coefficients
                coeffs[base+step] = coeffs[base] - y;
                coeffs[base] += y;
                base += jmp;
           }
           factor = factor * stride;
        }     
    }
    return;
}

// increments itr by 2^j-2 following  the rule that 
// 2^j-1 + 2^j-1 = 2^j-2 (everything is a neg. carry)
// this MUST be called with the correct values so that ind does not become
// neg
// pow MUST NOT be less than 2 
void OptimizedPSS::reverse_add(int& itr, int pow) {
    auto carry = (itr >> pow-2) & 1 + 1;
    int ind = pow-2;
    while ((((itr >> ind) & 1) + 1)  == 2) {
        auto mask = ~(1 << ind);
        itr &= mask;
        ind -= 1;
    }
    itr += (1 << ind);
}

// same as the version above, except we want to preserve the input
// it is assumed that coeffs.size() == ( 1 << nearest_pow)
vector<ZZ_p> OptimizedPSS::PreserveInDFT(vector<ZZ_p>& coeffs, int pow_u) {
    auto order_gr = (1 << pow_u);
    auto MASK = order_gr - 1;
    ZZ_p gen;
    if (pow_u == nearest_pow) {
        gen = generator;
    } else {
        gen = generator*generator;
    }

    vector<ZZ_p> out(order_gr);
    if (pow_u == 0) {
        out[0] = coeffs[0];
        return out;
    }
    else if (pow_u == 1) {
        out[0] = coeffs[0] + coeffs[1];
        out[1] = coeffs[0]-coeffs[1];
        return out;
    }

    // we're starting off not in the correct order for 
    // the coefficients. if we want to deal with this w.o
    // reordering, we'll need to do something special for the 
    // first run through of the loop 
    auto step = (1 << pow_u - 1);
    int base = 0; 
    for (int k = 0; k < step; k++) {
        // k and k+step are the *coefficients* under consider.
        // because coeffs doubles as the evaluation in order w^0 ... w^2^j-1
        // for the roots of unity,we will be forced to overwrite the coefficient of 2k+1
        // and since we will need it (shortly), we MUST save it somewhere
        auto k_d = 2*k;

        out[k_d] = coeffs[base] + coeffs[base+step];
        out[k_d+1] = coeffs[base] - coeffs[base+step]; 

        reverse_add(base, pow_u); 
    } 
    
    ZZ_p y, stride, factor; 
    for (int i = 1; i < pow_u; i++) {
        auto step = (1 << i); // 2^i
        auto jmp = 2*step; // 2^i+1
        // factor stride 
        stride = power(gen, order_gr >> (i+1)); // 2^(j-i-1)
        factor = fieldType->GetElement(1);
        for (int k = 0; k < step; k++) {
            auto base = k;
            while (base < order_gr) { 
                // pair spots are step apart 
                // j*jmp +k,  +k + step
                y = factor * out[base+step]; 
                // update coefficients
                out[base+step] = out[base] - y;
                out[base] += y;
                base += jmp;
           }
           factor = factor * stride;
        }     
    }
    return out; 
}

void OptimizedPSS::InvDFT(vector<ZZ_p>& sample_pts, int pow_u, int end) {
    DFT(sample_pts, pow_u);
    // multiply 1/(1 << nearest_pow) 
    ZZ_p n_inv = inv(fieldType->GetElement(1<<pow_u));
    int MASK = (1 << pow_u) - 1;
    
    if (end <  1 << (pow_u - 1)) {
        for (int i = 0; i < end; i++) {
            int new_idx = ((1 << pow_u) - i) & MASK; 
            sample_pts[i] = n_inv * sample_pts[new_idx];
        }
    } else {
        for (int i = 0; i < 1 << (pow_u-1); i++) {
            auto save = sample_pts[i];
            int new_idx = ((1 << pow_u) - i) & MASK; 
            sample_pts[i] = n_inv * sample_pts[new_idx];
            sample_pts[new_idx] = n_inv * save;
        }
        sample_pts[1 << (pow_u-1)] *= n_inv; 
    }
    sample_pts.erase(sample_pts.begin() + end, sample_pts.end());
    return;
}

template <class FieldType>
class PackedSecretShare {
private:
	vector<FieldType> secrets;
	//FieldType& operator[](int idx);

public:
	PackedSecretShare(int l, int d, int n, HIM<FieldType> *mtx, TemplateField<FieldType>* fieldType);
	int l;
	int d;  
	int n;
	FieldType myShare;

	FieldType& operator[](int idx);

	TemplateField<FieldType> *field;
	HIM<FieldType> *recoverMTX;
	// returns a vector of secrets 
	vector<FieldType> recoverSS(vector<FieldType> samplePoints);
	vector<FieldType> secretShareValues(HIM<FieldType>* packSS);
	vector<FieldType> calcMinPoly(HIM<FieldType>* him);

	bool operator==(const PackedSecretShare<FieldType>& other);
	bool operator!=(const PackedSecretShare<FieldType>& other);

	void setMyShare(FieldType val);
	void generateRandomSecrets();
	void generateRandomDupSecret();
	void setSecrets(const vector<FieldType>& secret_vals);
};

template<class FieldType>
FieldType& PackedSecretShare<FieldType>::operator[](int idx){
	if (idx >= l) {
		throw invalid_argument("Trying to access a secret value outsid of pack range");
	}
	if (secrets.size() == 0) {
		throw invalid_argument("Secret values not set!! Can't call this function :(");
	}
	return secrets[idx];
}

template<class FieldType>
void PackedSecretShare<FieldType>::setMyShare(FieldType val) {
	myShare = val;
}

template<class FieldType>
bool PackedSecretShare<FieldType>::operator==(const PackedSecretShare<FieldType>& other) {
	if (this->l != other.l) {
		return false;
	}
	for (int i=0;i<this->l;i++) {
		if (this->secrets[i] != other.secrets[i]) {
			return false;
		}
	}
	return true;
}

template<class FieldType>
bool PackedSecretShare<FieldType>::operator!=(const PackedSecretShare<FieldType>& other) {
	return !(*this == other);
}

template<class FieldType>
void PackedSecretShare<FieldType>::generateRandomSecrets() {
	secrets.resize(l);
	for (int k = 0; k < l; k++) {
    	secrets[k] = field->Random();
    }
}

template<class FieldType>
void PackedSecretShare<FieldType>::setSecrets(const vector<FieldType>& secret_vals) {
	int num_secrets = secret_vals.size();
	if (num_secrets > this->l) {
		throw invalid_argument("Number of secrets you want to pack is over threshold!!");
	}
	this->secrets.resize(num_secrets);
	for (int z=0;z<num_secrets;z++) {
		this->secrets[z] = secret_vals[z];
	}
}

template<class FieldType>
PackedSecretShare<FieldType>::PackedSecretShare(int l, int d, int n, HIM<FieldType> *mtx, TemplateField<FieldType>* fieldType): l(l), d(d), n(n) {
	field = fieldType;	
	recoverMTX = mtx;
}

template<class FieldType>
vector<FieldType> PackedSecretShare<FieldType>::recoverSS(vector<FieldType> allPoints)
{
	// degree of poly *should be* t so # points needed for sample
	// is t + 1, it is also expected that this is in the correct order....
	int numPoints = allPoints.size();
    /*
	if (numPoints != n) {
		cout << "Party is offline, quitting for now...." << endl;
		exit(0);
	}
	*/
	vector<FieldType> samplePoints;
	samplePoints.resize(d+1);

	for (int i = 0; i < d+1; i++)  {
		samplePoints[i] = allPoints[i];
	}

	
	vector<FieldType> recoverPts;
	// not sure if this is needed or not
	recoverPts.resize(n-(d+1)+l);
	recoverMTX->MatrixMult(samplePoints, recoverPts);
	// check consistency

	for (int j = 0; j < numPoints-(d+1); j++) {
		if (recoverPts[l+j] != allPoints[1+d+j]) {
			cout << "Party " << to_string(1+d+j) << " is cheating!" << endl;
			cout << "Recovered point: " << recoverPts[l+j] << endl;
			cout << "Point provided: " << allPoints[1+d+j]<< endl;
			exit(1);
		}
	}
	// drop the end
	recoverPts.erase(recoverPts.begin()+l,recoverPts.end());
	secrets = recoverPts;
	return recoverPts;
}

template<class FieldType>
vector<FieldType> PackedSecretShare<FieldType>::secretShareValues(HIM<FieldType>* packSS) {
	vector<FieldType> yValues;

	for (int i = 0; i < d+1; i++) {
		if (i < l && secrets.size()>i) {
			yValues.push_back(secrets[i]); 
		} else if (i < l){
            yValues.push_back(field->GetElement(0));
        } else {
			yValues.push_back(field->Random());
		}
	} 

	vector<FieldType> lastsharePts;
	lastsharePts.resize(n-(d+1)+l);
	packSS->MatrixMult(yValues, lastsharePts);

	vector<FieldType> allSharePts;
	allSharePts.reserve(n);
	allSharePts.insert(allSharePts.end(), yValues.begin()+l, yValues.end());
	allSharePts.insert(allSharePts.end(), lastsharePts.begin(), lastsharePts.end());
	if (allSharePts.size() != n) {
		cout << "allSharePoints is not of the correct size" << endl;
		exit(1);
	}
	return allSharePts;
}
// calc. deg. l-1 poly. f(x) st f(e_i)=s_i
// and return pt f(idx) 
template <class FieldType>
vector<FieldType> PackedSecretShare<FieldType>::calcMinPoly(HIM<FieldType>* him) {
	if (secrets.size() != l) {
		throw invalid_argument("secrets array not set");
	}
	// secret share l -1 poly.
	// this IS exp. atm, could not be in the future...
	vector<FieldType> res(n);
	him->MatrixMult(secrets,res);
	return res;
}


#endif

// becgabri (6/19/2022)


#include "PackedSS.hpp"
#include "TemplateField.h"
#include "libscapi_utils/include/primitives/Mersenne.hpp"
#include "libscapi_utils/include/primitives/Matrix.hpp"
#include <vector>
#include <iostream>
#include <cmath>
#include <cstdlib>
#include <ctime>

using namespace std;

int main() {
    srand(time(0)); // this is just used for testing 
    long field_size = 3193032821761;
    TemplateField<ZZ_p> tempField(field_size);
    auto l = 12;//2;//1;
    auto t = 25;//1;//1;
    auto d = t + 2*l -1;
    auto num_parties = 100;//11;//5;
    OptimizedPSS pss1(l,d,num_parties, field_size, &tempField);
   
    int nearest_pow = ceil(log2(num_parties+l));
    /*
    int test_deg = d+1;//rand()%(1<<nearest_pow-1);
    cout << "Test degree is " << test_deg << endl;
    vector<ZZ_p> coeff(test_deg);
    for (int i = 0; i < test_deg; i++) {
        coeff[i] = tempField.Random();
    }
    cout << "Test coefficient vector is " << endl;
    printCV(coeff);
    vector<ZZ_p> copy_coeff(coeff.begin(), coeff.end());
    
    // do DFT evaluation for both 
    cout << "This is evauluation with both DFTs" << endl;
    pss1.prepareCoeffs(coeff, nearest_pow);
    pss1.DFT(coeff, nearest_pow);
    pss1.prepareCoeffs(copy_coeff, nearest_pow-1);
    pss1.DFT(copy_coeff, nearest_pow-1);

    printRoots(coeff); 
    printRoots(copy_coeff);

    vector<ZZ_p> for_invdft(copy_coeff.begin(), copy_coeff.end());
    pss1.InvDFT(for_invdft, nearest_pow-1, for_invdft.size());
    cout << "output of inverse dft for nearest_pow-1" << endl;
    printCV(for_invdft);
    // first step in this recover is attempted with the reg. coefficients
    copy_coeff.erase(copy_coeff.begin()+test_deg, copy_coeff.end()); 
    auto rptc = pss1.ptToCoeff(copy_coeff,nearest_pow-1,true);    
    cout << "recovered coefficients from nearest_pow -1 were " << endl;
    printCV(rptc);
    vector<ZZ_p> pts_for_recov(d+1);
    // take the rest of the small fry 
    auto end = l+d+1 < (1 << nearest_pow-1) ? d+1 : (1 << nearest_pow-1) - l;
    for (int i = 0; i < end; i++) {
        pts_for_recov[i] = coeff[2*(l+i)];
    } 
    for (int i = 0; i < (d+1)-end; i++) {
        pts_for_recov[end+i] = coeff[2*i+1];
    }
    auto rptc2 = pss1.ptToCoeff(pts_for_recov, nearest_pow, false);
    cout << "recovered coefficients from nearest pow were " << endl;
    printCV(rptc2);
    */
    ZZ_p field_elt = tempField.GetElement(14);
    ZZ_p root = power(field_elt, (field_size-1) / (1 << nearest_pow));
    
    int test_deg = rand()%(1 << nearest_pow); 
    if (test_deg == 0) {
        test_deg = 1;
    }
    //int test_deg = 2;
    vector<ZZ_p> coeff(test_deg);
    for (int i = 0; i < test_deg; i++) {
        coeff[i] = tempField.Random();
        cout << coeff[i] << "x^" << i << " + ";
    }
    cout << endl;
    vector<ZZ_p> copy_coeff(coeff.begin(), coeff.end());
    cout << "Before prepareCoeffs" << endl;
    printCV(coeff);
    pss1.prepareCoeffs(coeff, nearest_pow);
    cout << "After prepareCoeffs" << endl;
    printCV(coeff);
    pss1.DFT(coeff, nearest_pow); // a(1) ... a(2^j)
    // VDM matrix 
    VDM<ZZ_p> vdm_test(num_parties,test_deg,&tempField);
    // need to do what was done earlier 
    vector<ZZ_p> vdm_roots; 
    for (int i = 0 ; i < num_parties; i++) {
       vdm_roots.push_back(power(root, i));
    }
    cout << "Roots used for VDM" << endl;
    vdm_test.InitVDM(vdm_roots);

    vector<ZZ_p> ans_v(num_parties);
    cout << "VDM coefficient matrix is" << endl;
    printCV(copy_coeff);
    vdm_test.MatrixMult(copy_coeff, ans_v, test_deg);
    cout << "VDM Method" << endl;
    printRoots(ans_v);
    cout << "FFT Method" << endl;
    printRoots(coeff);
    for (int i = 0; i < num_parties; i++) {
        if (ans_v[i] != coeff[i]) { 
            cout << "Pos " << i << endl;
            cout << "LHS: " << ans_v[i] << endl;
            cout << "RHS: " << coeff[i] << endl;
            throw std::invalid_argument("Incorrect! The values differ between secret sharing techniques!!");
        }    
    }
    cout << "Success!" << endl;
    // Test InvDFT
    cout << "Testing InvDFT" << endl;
    //pss1.prepareCoeffs(coeff); 
    cout << "Coefficients should be " << endl;
    printCV(copy_coeff);
    pss1.InvDFT(coeff, nearest_pow, test_deg);
    for (int i = 0; i < test_deg; i++) {
        if (copy_coeff[i] != coeff[i]) {
            cout << "At position " << i << " the coefficient should be " << copy_coeff[i] << " but we recovered " << coeff[i] << endl;
            throw std::invalid_argument("Incorrect InvDFT function!");
        }
    }
    cout << "Success!" << endl;
    cout << "Testing Polynomial Multiplication" << endl;
    vector<ZZ_p> a(2);
    vector<ZZ_p> b(2);
    cout << "Poly A: (";
    
    for (int i = 0; i < 2; i++) {
        a[i] = tempField.Random();
        cout << a[i] << ",";
    }
    cout << ")" << endl;

    
    cout << "Poly B: (";
    for (int i = 0; i < 2; i++) {
        b[i] = tempField.Random();
        cout << b[i] << ",";
    }
    cout << ")" << endl;
    vector<ZZ_p> correct_res(3);
    correct_res[0] = a[0] * b[0];
    correct_res[2] = a[1] * b[1];
    correct_res[1] = (a[1] * b[0]) + (a[0] * b[1]);
    pss1.polyMult(a, b);
    cout << "Poly C: ";
    printCV(a);
    cout << "*Correct* Poly C: ";
    printCV(correct_res);

    for (int i = 0; i < a.size(); i++) {
        if (a[i] != correct_res[i]) {
            throw std::invalid_argument("Polynomial multiplication failed!");
        } 
    }
    cout << "Test 2, poly mult different sizes" << endl;
    vector<ZZ_p> f(2);
    vector<ZZ_p> g(1);
    cout << "Poly F: (";
    for (int i = 0; i < f.size(); i++) {
        f[i] = tempField.Random();
        cout << f[i] << ",";
    }
    cout << ")" << endl;
    cout << "Poly G: (";
    for (int i = 0; i < g.size(); i++) {
        g[i] = tempField.Random();
        cout << g[i] << ",";
    }
    cout << ")" << endl;

    vector<ZZ_p> z_correct(2);
    z_correct[0] = f[0] * g[0];
    z_correct[1] = f[1] * g[0];

    pss1.polyMult(f,g);
    cout << "Poly Z: (";
    for (int i = 0; i < f.size(); i++) {
        cout << f[i] << ",";
    }
    cout << ")" << endl;
    for ( int i = 0; i < f.size(); i++) {
        if (z_correct[i] != f[i]) {
            throw std::invalid_argument("Polynomial multiplication was wrong!");
        }
    }
    vector<ZZ_p> sec; 
    cout << "Has secret points" << endl;
    for (int i = 0; i < l; i++) {
        auto secret_pt = tempField.Random();
        cout << "Point " << i << " is " << secret_pt << endl;
        sec.push_back(secret_pt);
    }

    pss1.setSecrets(sec);
    auto got_pts = pss1.secretShareValues();    
    cout << "Points for parties:" << endl;
    for ( auto it = 0; it < got_pts.size(); it++ ) {
        cout << "Party "<< it << " has point " << got_pts[it] << endl;
    } 
    //got_pts.erase(got_pts.begin()+t+1, got_pts.end());
    auto recover_secrets = pss1.recoverSS(got_pts);
    if (recover_secrets.size() != sec.size()) {
        cout << "Size of recovered secrets isn't even right!" << endl;
    }
    for (int i = 0; i < recover_secrets.size(); i++) {
        if (recover_secrets[i] != sec[i]) {
            cout << "Error! " << recover_secrets[i] << " neq " << sec[i] << " at position " << i << endl;
             throw invalid_argument("Failed!");
        }
    }
    cout << "Passed tests!" << endl;
}

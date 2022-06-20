// becgabri (06/19/2022)

#include "PackedSS.hpp"
#include "TemplateField.h"
#include "testVDM.hpp"
#include <libscapi/include/primitives/Mersenne.hpp>
#include <libscapi/include/primitives/Matrix.hpp>
#include <vector>
#include <iostream>
#include <cmath>
#include <chrono>
#include <algorithm> 

using namespace std;

int main() {
    // from the c++ examples at https://www.cplusplus.com/reference/chrono/steady_clock/
    using namespace std::chrono;

    long field_size = 3193032821761;
    TemplateField<ZZ_p> tempField(field_size);
    auto l = 12;//62;//12;
    auto t = 25;//125;//25;
    auto d = t + 2*l -1;
    auto num_parties = 100;//500;//100;
    OptimizedPSS pss1(l,d,num_parties, field_size, &tempField);
    /*             
    int nearest_pow = ceil(log2(num_parties+l));
    vector<ZZ_p> alpha_roots;
    alpha_roots.reserve(d+1);
    vector<ZZ_p> secret_roots;
    secret_roots.reserve(l+(num_parties-d-1));
    ZZ_p field_elt = tempField.GetElement(14);
    ZZ_p root = power(field_elt, (field_size-1) / (1 << nearest_pow));
    for (int i = 0; i < d+1; i++) {
        alpha_roots.push_back(power(root,l+i));
    }
    for (int i = 0; i < l; i++) {
        secret_roots.push_back(power(root,i));
    } 
    for (int i = 0; i < num_parties-d-1; i++) {
        secret_roots.push_back(power(root, l+d+1+i));
    }
    HIM<ZZ_p> recoverMtx;
    // row by col
    recoverMtx.allocate(l+(num_parties-d-1), d+1, &tempField); 
    recoverMtx.InitHIMByVectors(alpha_roots, secret_roots);
    secret_roots.erase(secret_roots.begin()+l, secret_roots.end());
    secret_roots.insert(secret_roots.end(), alpha_roots.begin(), alpha_roots.begin()+(d+1)-l);
    vector<ZZ_p> eval_pts;
    eval_pts.reserve(num_parties-(d+1)-l);
    for (int i = 0; i < num_parties-(d+1)-l; i++) {
        eval_pts.push_back(power(root, d+1+ i));
    }
    HIM<ZZ_p> shareMtx;
    shareMtx.allocate(num_parties-(d+1-l),d+1, &tempField);
    shareMtx.InitHIMByVectors(secret_roots, eval_pts);
    PackedSecretShare<ZZ_p> reg_pss1(l,d,num_parties, &recoverMtx,&tempField);
    */
    vector<ZZ_p> sec; 
    for (int j = 0; j < l; j++) {
        auto secret_pt = tempField.Random();
        sec.push_back(secret_pt);
    }
    pss1.setSecrets(sec);
    //reg_pss1.setSecrets(sec);
    int NUM_REPEATS = 10000;
    //vector<nanoseconds> avg_reg_time(NUM_REPEATS);
    vector<nanoseconds> avg_opt_time(NUM_REPEATS); 
    for (int i = 0; i < NUM_REPEATS; i++) {
       /*      
       steady_clock::time_point reg_start = steady_clock::now();
       reg_pss1.secretShareValues(&shareMtx);
       steady_clock::time_point reg_end = steady_clock::now();
       avg_reg_time[i] = duration_cast<nanoseconds>(reg_end-reg_start);
       */
       steady_clock::time_point opt_start = steady_clock::now();
       pss1.secretShareValues();
       steady_clock::time_point opt_end = steady_clock::now();
       avg_opt_time[i] = duration_cast<nanoseconds>(opt_end-opt_start);
    
    }
    //nanoseconds avg_reg(0);
    nanoseconds avg_opt(0);
    for ( int j = 0; j < NUM_REPEATS; j++) {
        //avg_reg += avg_reg_time[j];
        avg_opt += avg_opt_time[j];
    }
    // do a sort 
    //sort(avg_reg_time.begin(), avg_reg_time.end());
    sort(avg_opt_time.begin(), avg_opt_time.end());
    // cout << "Avg reg. time: " << avg_reg.count()/NUM_REPEATS << endl;
    cout << "Avg opt. time: " << avg_opt.count()/NUM_REPEATS << endl;
    //cout << "Median reg. time: " << avg_reg_time[NUM_REPEATS/2].count() << endl;
    cout << "Median opt. time: " << avg_opt_time[NUM_REPEATS / 2].count() << endl;
}

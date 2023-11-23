#pragma once

#ifndef _ZP_H
#define _ZP_H

#include <x86intrin.h> // simd, support 128-bit register
#include "NTL/ZZ.h"
#include "NTL/ZZ_p.h"
#include "gmp.h"

#include <sstream>
#include <string>
#include <vector>

using namespace NTL;

class ZpLongEle {

public:
    static const unsigned long long p = 2305843009213693951;
    unsigned long long ele;

    ZpLongEle() { ele = 0; };
    ZpLongEle(unsigned long e) { 
        this->ele = e; 
        if (this->ele >= p) {
            this->ele = (this->ele & p) + (this->ele >> 61);

            if (this->ele >= p) this->ele -= p;
        }
    };
    
    // check equal
    bool operator!=(const ZpLongEle& other) { return other.ele != ele; };

    // assign
    inline ZpLongEle& operator=(const ZpLongEle& other) { ele = other.ele; return *this; };
    
    // add
    ZpLongEle operator+(const ZpLongEle& other) { 
        ZpLongEle ans;
        ans.ele = (ele + other.ele);

        if (ans.ele >= p) ans.ele -= p;
        return ans;
    };

    // minus
    ZpLongEle operator-(const ZpLongEle& other) { 
        ZpLongEle ans;

        int64_t temp = ele - other.ele;

        if (temp < 0) {
            ans.ele = temp + p;
        } else {
            ans.ele = temp;
        }

        return ans;
    };

    ZpLongEle operator*(const ZpLongEle& other) {
        ZpLongEle ans;

        unsigned long long high;
        // store the low 64-bits of the result in low, and store the high 64-bits in hi
        unsigned long long low = _mulx_u64(ele, other.ele, &high);
        
        unsigned long long low61 = (low & p);
        unsigned long long res = (low61 + (low >> 61) + (high << 3));

        if (res >= p) {
            res -= p;
        }

        ans.ele = res;

        return ans;
    }   

    // div (using exgcd)
    // \frac{this}{other} = this \cdot ( other^{-1} mod p )
    ZpLongEle operator/(const ZpLongEle& other) {
        ZpLongEle answer;
        mpz_t d;
        mpz_t result;
        mpz_t mpz_elem;
        mpz_t mpz_me;
        mpz_init_set_str(d, "2305843009213693951", 10);
        mpz_init(mpz_elem);
        mpz_init(mpz_me);

        mpz_set_ui(mpz_elem, other.ele);
        mpz_set_ui(mpz_me, ele);

        mpz_init(result);

        mpz_invert(result, mpz_elem, d);

        mpz_mul(result, result, mpz_me);
        mpz_mod(result, result, d);

        answer.ele = mpz_get_ui(result);

        return answer;
    }

    ZpLongEle& operator+=(const ZpLongEle& other) {
        ele = (ele + other.ele);

        if (ele >= p) {
            ele -= p;
        }
        return *this;
    }

    ZpLongEle& operator*=(const ZpLongEle& other) {

        unsigned long long high;
        // store the low 64-bits of the result in low, and store the high 64-bits in hi
        unsigned long long low = _mulx_u64(ele, other.ele, &high);
        
        unsigned long long low61 = (low & p);
        unsigned long long res = (low61 + (low >> 61) + (high << 3));

        if (res >= p) {
            res -= p;
        }        

        ele = res;

        return *this;
    }
};

#endif
#pragma once

#ifndef _POLY_H
#define _POLY_H

#include <omp.h>
#include "zp.h"

class Poly {
    public:
        static void eval(ZpLongEle& Y, const std::vector<ZpLongEle>& co, ZpLongEle X);
        static void interpolate(std::vector<ZpLongEle>& co, const std::vector<ZpLongEle>& X, std::vector<ZpLongEle>& Y);
};

#endif
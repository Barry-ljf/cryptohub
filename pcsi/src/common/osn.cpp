#include <cstdio>
#include <cstring>
#include <vector>
#include <iostream>
#include <math.h>
#include <bits/stdc++.h> 
using namespace std;

#include <cryptoTools/Common/BitVector.h>

std::vector<int> perm;
std::vector<int> inv_perm;
std::vector<std::vector<int>> switched;

const int benes_size = 1.27*(1 << 20);
static char path[benes_size];

inline void swap(uint64_t& a, uint64_t& b) {
	uint64_t tmp;
    tmp = b;
    b = a;
    a = tmp;
}

void initialize(int values, int levels) {
    perm.resize(values);
    inv_perm.resize(values);
    switched.resize(levels);
    for (int i= 0; i < levels; ++i) {
		switched[i].resize(values/2);
	}
}                   


void DFS(int idx, int route) {
    stack<pair<int, int> > st; 
    st.push({idx, route});
    pair<int, int> pr;
    while (!st.empty()) {
		pr = st.top();
		st.pop();
		path[pr.first] = pr.second;
		if (path[pr.first ^ 1] < 0) {
			st.push({pr.first ^ 1, pr.second ^ 1});
		}

		idx = perm[inv_perm[pr.first] ^ 1];
		if (path[idx] < 0) {
			st.push({idx, pr.second ^ 1});
		}
	} 
}

int shuffle(int i, int n) { 
  	return ((i & 1) << (n - 1)) | (i >> 1); 
}

void route(int n, int cur_level, int index, const vector<int> &src, const vector<int> &dest) {

    int levels, i, j, x, s;
    vector<int> bottom1;
    vector<int> top1;
    int values = src.size();

    // the same cur_level of layer can be simultaneously processed
    // process when element size is 2
    if (values == 2) {
      	if (n == 1) {
			switched[cur_level][index] = src[0] != dest[0]; 
		} else {
			switched[cur_level+1][index] = src[0] != dest[0];
		}
      	return; 
    }

    // process when element size is 3
    if (values == 3) {

      if (src[0] == dest[0]) {
        switched[cur_level][index] = 0;
        switched[cur_level+2][index] = 0;
        if (src[1] == dest[1]) {
			switched[cur_level+1][index] = 0;   // 1 2 3 -> 1 2 3
		} else {
			switched[cur_level+1][index] = 1;   // 1 2 3 -> 1 3 2
		}
          
      }

      if (src[0] == dest[1]) {
        switched[cur_level][index] = 0;
        switched[cur_level+2][index] = 1;
        if (src[1] == dest[0])  {
			switched[cur_level+1][index] = 0;   // 1 2 3 -> 2 1 3
		} else {
          	switched[cur_level+1][index] = 1;   // 1 2 3 -> 3 1 2
		}
      }

      if (src[0] == dest[2]) {
        switched[cur_level][index] = 1;
        switched[cur_level+1][index] = 1;
        if (src[1] == dest[0]) {
			switched[cur_level+2][index] = 0;   // 1 2 3 -> 2 3 1
		} else {
			switched[cur_level+2][index] = 1;   // 1 2 3 -> 3 2 1
		} 
      }
	  
      return;
    }

    levels = 2 * n - 1;
    
    vector<int> bottom2(values / 2);
    vector<int> top2(int(ceil(values*0.5)));

    for (i = 0; i < values; ++i) {
		inv_perm[src[i]] = i;
	}
  
    for (i = 0; i < values; ++i) {
		perm[i] = inv_perm[dest[i]];
	}
  
    for (i = 0; i < values; ++i) {
		inv_perm[perm[i]] = i;
	}

    memset(path, -1, sizeof(path));
    if (values & 1) {
      	path[values - 1] = 1;   
      	path[perm[values - 1]] = 1; 
      	if (perm[values - 1] != values - 1) {
        	int idx = perm[inv_perm[values - 1] ^ 1];
        	DFS(idx, 0);
     	}
    }

    for (i = 0; i < values; ++i)
      	if (path[i] < 0) {
        	DFS(i, 0);
      	}

    for (i = 0; i < values - 1; i += 2) {
      	switched[cur_level][index + i / 2] = path[i];
      	for (j = 0; j < 2; ++j) {
        	x = shuffle((i | j) ^ path[i], n);
        	if (x < values / 2) {
          		bottom1.push_back(src[i | j]); 
        	} else {
          		top1.push_back(src[i | j]);
        	}
      	}
    }

    if (values & 1) {
      	top1.push_back(src[values - 1]);
    }

    for (i = 0; i < values - 1; i += 2) {
		s = switched[cur_level + levels - 1][index + i / 2] = path[perm[i]];
		for (j = 0; j < 2; ++j) {
			x = shuffle((i | j) ^ s, n);
			if (x < values / 2) {
				bottom2[x] = src[perm[i | j]]; 
			} else {
				top2[i / 2] = src[perm[i | j]];
			}
		}
    }

    int idx =int(ceil(values*0.5));
    if (values & 1) {
		top2[idx-1] = dest[values-1];
    }

    route(n - 1, cur_level + 1, index, bottom1, bottom2);
    route(n - 1, cur_level + 1, index + values / 4, top1, top2);
}

void masked_eval (int n, int cur_level, int index, vector<uint64_t> &src, vector<vector<osuCrypto::block>> &ot_output) {
	int levels, i, j, x, s;
	vector<uint64_t> bottom1;
	vector<uint64_t> top1;
	int values = src.size();
	uint64_t tmp_int[2];
	osuCrypto::block tmp_block;

	if (values == 2) {
		if (n == 1) {
			tmp_block = ot_output[cur_level][index];
			memcpy(tmp_int, &tmp_block, sizeof(tmp_int));
			src[0] ^= tmp_int[0];
			src[1] ^= tmp_int[1];
			if (switched[cur_level][index] == 1) {
				swap(src[0], src[1]);
			}  
		} else {
			tmp_block = ot_output[cur_level + 1][index];
			memcpy(tmp_int, &tmp_block, sizeof(tmp_int));
			src[0] ^= tmp_int[0];
			src[1] ^= tmp_int[1];
			if (switched[cur_level + 1][index] == 1) {
				swap(src[0], src[1]);
			} 
		} 
		return; 
	}

	if (values == 3) {
		tmp_block = ot_output[cur_level][index];
		memcpy(tmp_int, &tmp_block, sizeof(tmp_int));
		src[0] ^= tmp_int[0];
		src[1] ^= tmp_int[1];
		if(switched[cur_level][index] == 1) {
			swap(src[0], src[1]);
		}


		tmp_block = ot_output[cur_level + 1][index];
		memcpy(tmp_int, &tmp_block, sizeof(tmp_int));
		src[1] ^= tmp_int[0];
		src[2] ^= tmp_int[1];
		if(switched[cur_level + 1][index] == 1) {
			swap(src[1], src[2]);
		}


		tmp_block = ot_output[cur_level + 2][index];
		memcpy(tmp_int, &tmp_block, sizeof(tmp_int));
		src[0] ^= tmp_int[0];
		src[1] ^= tmp_int[1];
		if(switched[cur_level + 2][index] == 1) {
			swap(src[0], src[1]);
		}
		return;
	}
	
	levels = 2 * n - 1;
	
	for (i = 0; i < values - 1; i += 2) {
		int s = switched[cur_level][index + i / 2];
		
		tmp_block = ot_output[cur_level][index+i/2];
		memcpy(tmp_int, &tmp_block, sizeof(tmp_int));

		src[i] ^= tmp_int[0];
		src[i ^ 1] ^= tmp_int[1];

		for (j = 0; j < 2; j++) {
			x = shuffle((i | j) ^ s, n);
			if (x < values / 2) {
				bottom1.push_back(src[i | j]);
			} else {
				top1.push_back(src[i | j]);
			} 
		}
	}

	if (values & 1){
		top1.push_back(src[values-1]);
	}

	masked_eval(n - 1, cur_level + 1, index, bottom1, ot_output);
	masked_eval(n - 1, cur_level + 1, index + values / 4, top1, ot_output);


	for (i = 0; i < values - 1; i += 2) {
		s = switched[cur_level + levels - 1][index + i / 2];

		for (j = 0; j < 2; ++j) {
			x = shuffle((i | j) ^ s, n);
			if (x < values / 2) {
				src[i | j] = bottom1[x]; 
			} else {
				src[i | j] = top1[i/2];
			}
		}

		tmp_block = ot_output[cur_level + levels - 1][index+i/2];
		memcpy(tmp_int, &tmp_block, sizeof(tmp_int));
		src[i] ^= tmp_int[s];
		src[i ^ 1] ^= tmp_int[1-s];  
	}

	int idx =int(ceil(values * 0.5));
	if (values & 1) {
		src[values - 1] = top1[idx - 1];
	}

  
}


osuCrypto::BitVector retrieve_switches(int values) {
	int n = int(ceil(log2(values)));
	int levels = 2 * n - 1;
	osuCrypto::BitVector switches(levels * (values / 2));
	for (int i = 0; i < levels; i++) {
		for (int j = 0; j < values/2; j++) {
			switches[i * (values/2) + j] = switched[i][j];
		}
	}
	return switches;
} 

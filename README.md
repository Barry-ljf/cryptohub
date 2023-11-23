# Crypto Library In Primihub
-------

This repository offers several practical instance of **Multi-Party Computation (MPC)** techniques available for use, including Privacy-Preserving Set Intersection (PSI, PCSI), Distributed SM2 Signatures, and more.

We have developed numerous MPC techniques, which will serve as the cryptographic foundation for building more privacy-preserving applications on **Primihub** in the future. This repository will integrate more SOTA cryptographic algorithms and will be fully open-source .

## Overview
-------
The algorithms included in this repository are based on extensive research. In the upcoming sections, we will introduce the functionality of the code after integration and development, as well as the underlying protocol support. We provide a rich set of example programs for use and offer corresponding compilation and runtime instructions for cryptographic functionality in different domains.

## Distributed SM2 Signatures
-------

This section implements the process of SM2 (a Chinese cryptographic algorithm) signatures and their verification based on distributed keys.

### Build && Run
---

**1. distributed_signer_test**

**Build**

bazel build --config=linux_x86_64 //test:test_distributed_sm2_signature

**Run**

./bazel-bin/test/test_distributed_sm2_signature --config=linux_x86_64



**2. distributed_signer_debug**

**Build**

bazel build --config=linux_x86_64 //test:debug_distributed_sm2_signature

**Run**

./bazel-bin/test/debug_distributed_sm2_signature --config=linux_x86_64




## PCSI Sum
-------

This section implements Private Set Intersection (PSI) using Cuckoo Hashing, Batch OPRF (Oblivious Pseudo-Random Function), and OSN (Oblivious Switching Network) technologies, and it can achieve the function to compute the cardinality sum of the intersection.

### Build && Run

**Build**

The current PCSI relies on specific instruction sets and the code includes submodules that require specifying particular versions. A detailed build process can be found in the readme.md file in the PCSI directory.


**Run**

After compilation, the corresponding executable files will be generated.

run command below:

```
./pcsi_test
```

## PSI
-------

This section primarily focuses on PSI-related technologies, including various Oblivious Transfer (OT) and  Programmable Pseudo-Random Function (PPRF) techniques.

### Build && Run

**1. Pprf**

**Build**

bazel build --config=linux //test:test_pprf

**Run**

./bazel-bin/test/test_pprf 

**2. Softspokenot**

**Build**

bazel build --config=linux //test:test_softspokenot

**Run**

./bazel-bin/test/test_softspokenot 



**3. Iknp**

**Build**

bazel build --config=linux //test:test_iknp

**Run**

./bazel-bin/test/test_iknp 


**4. Silentot** 

**Build**

bazel build --config=linux //test:test_silentot

**Run**

./bazel-bin/test/test_silentot 



**5. Vole**

**Build**

bazel build --config=linux //test:test_vole

**Run**

./bazel-bin/test/test_vole 


## Embedded
-------
Implementing SM2, SM3, SM4 for embedded devices.


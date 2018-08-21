# ICEPOLE Cryptanalysis

The __icepole_attack_20180814.pdf__ document specifies a method to uncover the key and nonce used with ICEPOLE encryption.
The following C/C++ project is an implementation of the specified attack. It consists of 2 projects:
- icepole - a clone of [ICEPOLE] implementation that is packed in a statically linked library. __Subject to the original licanse/copyright within the project__.
- icepole_cryptanalysis - a program that implements the attack on ICEPOLE. Copyright (c) 2018, Bar Ilan Cryptography Research Group. All rights reserved. See License.txt

## icepole
The icepole implementation code, forked off from [ICEPOLE], contains 3 implemented versions:
- icepole128av2.
- icepole128v2.
- icepole256av2.

The icepole128av2 is packed in a statically linked library.

## icepole_cryptanalysis
This program implements the specified attack in 3 phases:
- U03 phase - in this first phase the values of U3 and U0 are recovered.
- U2 phase - in this second phase the value of U2 is recovered.
- U1 phase - in this third phase the value of U1 is recovered.

The program's main thread runs each phase in turn. Since the results of each phase (i.e. the recovered values) are required by the subsequent phases, the three phases must run sequentially.
Each phase attack function launches 64 threads of attack, thus utilizing the 64 cores of the selected machine. Naturally the value of the attack threads constant can be changed (in compile time) in order to fit a machine with a different number of cores.
Each attack thread performs its share of the work and once all threads are done the results are summed and the target value is guessed based on the accumulated results.

[//]: # 
   [ICEPOLE]: https://github.com/icepole/icepole

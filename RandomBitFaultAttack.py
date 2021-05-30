#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import ctypes
from bitstring import BitArray

FAULT=7

class RandomBitFaultAttack:
    
    def __init__(self, key, v2=False):
        self.key = key
        self.v2 = v2
        
    def launch_attack(self, fun, reflection=0):
        if not self.v2:
            print ("****************************** Launching Random Bit Fault Attack on PRINCE ******************************\n"+105*"*")
            version = 1
        else:
            print ("****************************** Launching Random Bit Fault Attack on PRINCE v2 ******************************\n"+108*"*")
            version = 2
            
        print("Before Attack: =======================> ")
        if not self.v2:
            K0 = self.key[0:64]
            K0Prime = K0.copy()
            K0Prime.ror(1)
            K0Prime ^= K0 >> 63
            K1 = self.key[64:128]
            print("K0: \t",K0) 
            print("K1: \t",K1) 
            print("K0-Prime: \t",K0Prime) 
            print("K1 ^ K0-Prime: \t",K1^K0Prime)
        else:
            K0 = self.key[0:64]
            K1 = self.key[64:128]
            print("K0: \t",K0) 
            print("K1: \t",K1)
            
        fun.launch_attack.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long, ctypes.c_long, ctypes.c_int]
        
        if not self.v2:
            fun.launch_attack(FAULT, version, K1.int, (K1^K0Prime).int, reflection)
        else:
            fun.launch_attack(FAULT, version, K0.int, K1.int, reflection)
            


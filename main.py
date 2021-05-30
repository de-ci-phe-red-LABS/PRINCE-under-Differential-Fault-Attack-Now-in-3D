#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import argparse
import ctypes
import os
from bitstring import BitArray   
from IntegralAttack import IntegralAttack
from SlowDiffusionAttack import SlowDiffusionAttack
from RandomBitFaultAttack import RandomBitFaultAttack
            
if __name__ == "__main__":
    
#    p = BitArray("0x0123456789abcdef")
#    c = BitArray("0x59251f088012067c")
#    k = BitArray("0x0123456789abcdeffedcba9876543210")
#    obj = PRINCE_v2(k)
#    print (obj.encrypt(p))
#    print (obj.decrypt(c))
    
#    plainText = BitArray("0x0275371212374444")
#    key = BitArray("0x12341234567c0000ab01234abcdefaab")
    
    parser = argparse.ArgumentParser(description='Fault Attack on PRINCE and PRINCE_v2')
    parser.add_argument('-attack', type=int, help='Which attack? 1. Integral 2. Slow Diffusion', required=True)
    parser.add_argument('-version', type=int, help='Which PRINCE version? 1. PRINCE 2. PRINCE_v2', required=True)
    parser.add_argument('-reflection', help="Injection of fault at reflection point", action='store_true')
    args = parser.parse_args()
    attack = args.attack
    version = args.version
    reflection = 1 if args.reflection else 0
    
    if attack!=1 and attack!=2 and attack!=3:
        print ("Wrong choice for attack type !!!!!")
        exit(0)
    if version!=1 and version!=2:
        print ("Wrong choice for PRINCE version !!!!!")
        exit(0)
    
    if (attack==1 or attack==2):
        plainText = BitArray(hex="%016x"%random.randint(0,2**64))
        key = BitArray(hex="%032x"%random.randint(0,2**128))
        
        if not reflection:
            print ("Randomly generated plaintext and key:")
            print ("plaintext:\t",plainText)
        else:
            print ("Randomly generated ciphertext and key:")
            print ("ciphertext:\t",plainText)
        print ("key:\t",key)
        
    else:
        key = BitArray(hex="%032x"%random.randint(0,2**128))
        print ("Randomly generated key: \t", key)
    
    if (attack==1):
        if version==1:
            integralAttack = IntegralAttack(plainText, key, v2=False)
        else:
            integralAttack = IntegralAttack(plainText, key, v2=True)
        integralAttack.launch_attack(reflection)
    elif (attack==2):
        if version==1:
            slowDiffusionAttack = SlowDiffusionAttack(plainText, key, v2=False)
        else:
            slowDiffusionAttack = SlowDiffusionAttack(plainText, key, v2=True)
        slowDiffusionAttack.launch_attack(reflection)
    else:
        os.system("cc main.c -fPIC -shared -o libfun.so")
        fun = ctypes.CDLL("libfun.so")
        if version==1:
            randomBitFaultAttack = RandomBitFaultAttack(key, v2=False)
        else:
            randomBitFaultAttack = RandomBitFaultAttack(key, v2=True)
        randomBitFaultAttack.launch_attack(fun, reflection)
        
 
    
    
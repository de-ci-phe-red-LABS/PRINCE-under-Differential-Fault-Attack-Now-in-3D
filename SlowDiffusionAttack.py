#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
from bitstring import BitArray
from PRINCE import PRINCE
from PRINCE_v2 import PRINCE_v2

ALPHA = BitArray("0xc0ac29b7c97c50dd")
BETA = BitArray("0x3f84d5b5b5470917")

class SlowDiffusionAttack:
    
    def __init__(self, plainText, key, v2=False):
        self.plainText = plainText
        self.v2 = v2                                  # Variable for PRINCE v2
        if not self.v2:
            self.princeObj = PRINCE(key)
        else:
            self.princeObj = PRINCE_v2(key)
        self.cipherTexts = []
    
    # Function to generate all ciphertexts for Slow Diffusion attack     
    def generate_faulty_cipherTexts(self, reflection=0):
        for i in (0,1,2,4,8):                         # For Fault values - 1,2,4,8
            faultValue = BitArray("0x"+"%01x"%i+"%015x"%0)
            if not reflection:
                if not self.v2:
                    data = self.plainText ^ self.princeObj.k0 ^ self.princeObj.k1 ^ self.princeObj.RC[0]
                else:
                    data = self.plainText ^ self.princeObj.k0 ^ self.princeObj.RC[0]
                for idx in (1,2,3,4,5):
                    data = self.princeObj.forwardRound(data, idx)
                data = self.princeObj.middleRound(data)
                for idx in (6,7,8,9,10):
                    if (idx!=8):
                        data = self.princeObj.backwardRound(data, idx)
                    else:
                        if not self.v2:
                            data ^= self.princeObj.k1 ^ self.princeObj.RC[idx]     
                        else:
                            data ^= self.princeObj.k0 ^ self.princeObj.RC[idx]
                        data ^= faultValue                                     # Fault injection
                        data = self.princeObj.shiftRows(data, inverse=True)
                        data = self.princeObj.mPrime(data)
                        data = self.princeObj.substitution(data, inverse=True)
                if not self.v2:
                    data ^= self.princeObj.k0Prime ^ self.princeObj.k1 ^ self.princeObj.RC[11]
                else:
                    data ^= self.princeObj.k1 ^ self.princeObj.RC[11]
            else:
                if not self.v2:
                    self.princeObj.k1 ^= ALPHA
                    data = self.plainText ^ self.princeObj.k0Prime ^ self.princeObj.k1 ^ self.princeObj.RC[0]
                else:
                    tmp = self.princeObj.k0
                    self.princeObj.k0 = self.princeObj.k1
                    self.princeObj.k1 = tmp
                    self.princeObj.k0 ^= BETA
                    self.princeObj.k1 ^= ALPHA
                    data = self.plainText ^ self.princeObj.k0 ^ self.princeObj.RC[0]
                for idx in (1,2,3,4,5):
                    if (idx!=3):
                        data = self.princeObj.forwardRound(data, idx)
                    else:
                        data = self.princeObj.substitution(data, inverse=False)
                        data = self.princeObj.mPrime(data)
                        data = self.princeObj.shiftRows(data, inverse=False)
                        data ^= faultValue                                     # Fault injection
                        data ^= self.princeObj.RC[idx] ^ self.princeObj.k1
                if self.v2:
                    self.princeObj.k1 ^= ALPHA ^ BETA
                data = self.princeObj.middleRound(data)
                if self.v2:
                    self.princeObj.k0 ^= ALPHA ^ BETA
                for idx in (6,7,8,9,10):
                    data = self.princeObj.backwardRound(data, idx)
                if not self.v2:
                    data ^= self.princeObj.k0 ^ self.princeObj.k1 ^ self.princeObj.RC[11]
                    self.princeObj.k1 ^= ALPHA
                else:
                    data ^= self.princeObj.k1 ^ self.princeObj.RC[11]
                    self.princeObj.k0 ^= BETA ^ ALPHA ^ BETA
                    self.princeObj.k1 ^= ALPHA ^ ALPHA ^ BETA
                    tmp = self.princeObj.k0
                    self.princeObj.k0 = self.princeObj.k1
                    self.princeObj.k1 = tmp
                data = self.princeObj.encrypt(data)
            self.cipherTexts.append(data)
            
    # Function to reduce key-space of k0' xor k1 by matching the pattern with state 5 for 1st faulty ciphertext
    def check_pattern_state_5_ciphertext_1(self):
        K_0th_col=[]; K_1st_col=[]; K_2nd_col=[]; K_3rd_col=[]
        for i in range(2**16):
            k = BitArray("0x"+"%04x"%i+"%04x"%i+"%04x"%i+"%04x"%i)
            p0 = self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[0] ^ k ^ self.princeObj.RC[11], inverse=False))
            p1 = self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[1] ^ k ^ self.princeObj.RC[11], inverse=False))
            p = p0 ^ p1
            # Checking for inactivity
            if p[4:8]==BitArray("0x0"):   
                K_0th_col.append(i)
            if p[24:28]==BitArray("0x0"):
                K_1st_col.append(i) 
            if p[44:48]==BitArray("0x0"):
                K_2nd_col.append(i)
            if p[48:52]==BitArray("0x0"):
                K_3rd_col.append(i)
        
        return K_0th_col, K_1st_col, K_2nd_col, K_3rd_col
    
    # Function to reduce key-space of k0' xor k1 by matching the pattern with state 5 for jth faulty ciphertext
    def check_pattern_state_5_ciphertext_j(self, j, K_0th_col, K_1st_col, K_2nd_col, K_3rd_col):
        k0=[]; k1=[]; k2=[]; k3=[]
        for i in K_0th_col:
            k = BitArray("0x"+"%04x"%i+"%012x"%0)  # Checking for inactivity in column 1
            p0 = self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[0] ^ k ^ self.princeObj.RC[11], inverse=False))
            p1 = self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[j] ^ k ^ self.princeObj.RC[11], inverse=False))
            p = p0 ^ p1
            ind = (4*(j+0))%16
            if p[ind:ind+4]==BitArray("0x0") :
                k0.append(i)
        for i in K_1st_col:
            k = BitArray("0x"+"%08x"%i+"%08x"%0)  # Checking for inactivity in column 2
            p0 = self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[0] ^ k ^ self.princeObj.RC[11], inverse=False))
            p1 = self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[j] ^ k ^ self.princeObj.RC[11], inverse=False))
            p = p0 ^ p1
            ind = 16+(4*(j+1))%16
            if p[ind:ind+4]==BitArray("0x0") :
                k1.append(i) 
        for i in K_2nd_col:
            k = BitArray("0x"+"%012x"%i+"%04x"%0)  # Checking for inactivity in column 3
            p0 = self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[0] ^ k ^ self.princeObj.RC[11], inverse=False))
            p1 = self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[j] ^ k ^ self.princeObj.RC[11], inverse=False))
            p = p0 ^ p1
            ind = 32+(4*(j+2))%16
            if p[ind:ind+4]==BitArray("0x0"):
                k2.append(i)
        for i in K_3rd_col:
            k = BitArray("0x"+"%016x"%i)           # Checking for inactivity in column 4
            p0 = self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[0] ^ k ^ self.princeObj.RC[11], inverse=False))
            p1 = self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[j] ^ k ^ self.princeObj.RC[11], inverse=False))
            p = p0 ^ p1
            ind = 48+(4*(j+3))%16
            if p[ind:ind+4]==BitArray("0x0"):
                k3.append(i)
                
        return k0, k1, k2, k3
    
    # Function to merge the 4 column key spaces of k0' xor k1
    def merge(self, K_0th_col, K_1st_col, K_2nd_col, K_3rd_col):
        k0Prime_xor_k1 = []
        for i in K_0th_col:
            for j in K_1st_col:
                for k in K_2nd_col:
                    for l in K_3rd_col:
                        m=BitArray("0x"+"%04x"%i+"%04x"%j+"%04x"%k+"%04x"%l)
                        k0Prime_xor_k1.append(m)
        return k0Prime_xor_k1
    
    # Function to reduce key-space of k0' xor k1 and k1 by matching the pattern with state 3 for the faulty ciphertexts
    def check_pattern_state_3(self, k0Prime_xor_k1):
        K1_0th_col=[]; K1_1st_col=[]; K1_2nd_col=[]; K1_3rd_col=[]; k0123=[]
        
        # Matching the pattern with state 3 for 1st and 2nd faulty ciphertexts
        for k in k0Prime_xor_k1:
            p0 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[0] ^ k ^ self.princeObj.RC[11], inverse=False)), inverse=False)
            p1 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[1] ^ k ^ self.princeObj.RC[11], inverse=False)), inverse=False)
            p2 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[2] ^ k ^ self.princeObj.RC[11], inverse=False)), inverse=False)
            flag0=0; flag1=0; flag2=0; flag3=0
            key0=[]; key1=[]; key2=[]; key3=[]
            for j in range(2**16):     
                m = BitArray("0x"+"%04x"%j+"%04x"%j+"%04x"%j+"%04x"%j)
                p0_ = self.princeObj.mPrime(self.princeObj.substitution(p0 ^ self.princeObj.RC[10] ^ m, inverse=False))
                p1_ = self.princeObj.mPrime(self.princeObj.substitution(p1 ^ self.princeObj.RC[10] ^ m, inverse=False))
                p2_ = self.princeObj.mPrime(self.princeObj.substitution(p2 ^ self.princeObj.RC[10] ^ m, inverse=False))
                p = p0_ ^ p1_
                p_ = p0_ ^ p2_
                if p[0:4]!=BitArray("0x0") and p[4:16] == BitArray("0x000") and p_[0:4]!=BitArray("0x0") and p_[4:16] == BitArray("0x000"):
                    key0.append(j)
                    flag0=1
                if p[16:20]==BitArray("0x0") and p[20:24]!=BitArray("0x0") and p[24:32] == BitArray("0x00") and p_[16:20]==BitArray("0x0") and p_[20:24]!=BitArray("0x0") and p_[24:32] == BitArray("0x00"):
                    key1.append(j)
                    flag1=1
                if p[32:40]==BitArray("0x00") and p[40:44]!=BitArray("0x0") and p[44:48] == BitArray("0x0") and p_[32:48]==BitArray("0x0000"):
                    key2.append(j)
                    flag2=1
                if p[48:64]==BitArray("0x0000") and p_[48:60]==BitArray("0x000") and p_[60:64]!=BitArray("0x0"):
                    key3.append(j)
                    flag3=1
                    
            # Matching the pattern with state 3 for 3rd faulty ciphertexts
            if flag0==1 and flag1==1 and flag2==1 and flag3==1: 
                p3 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[3] ^ k ^ self.princeObj.RC[11], inverse=False)), inverse=False)
                flag0_=0; flag1_=0; flag2_=0; flag3_=0
                key0_=[]; key1_=[]; key2_=[]; key3_=[]
                for j in range(2**16):
                    m = BitArray("0x"+"%04x"%j+"%04x"%j+"%04x"%j+"%04x"%j)
                    p0_ = self.princeObj.mPrime(self.princeObj.substitution(p0 ^ self.princeObj.RC[10] ^ m, inverse=False))
                    p3_ = self.princeObj.mPrime(self.princeObj.substitution(p3 ^ self.princeObj.RC[10] ^ m, inverse=False))
                    p = p0_ ^ p3_
                    if p[0:4]!=BitArray("0x0") and p[4:16] == BitArray("0x000"):
                        if j in key0:
                            key0_.append(j)
                            flag0_=1
                    if p[16:32]==BitArray("0x0000"):
                        if j in key1:
                            key1_.append(j)
                            flag1_=1
                    if p[32:40]==BitArray("0x00") and p[40:44]!=BitArray("0x0") and p[44:48] == BitArray("0x0"):
                        if j in key2:
                            key2_.append(j)
                            flag2_=1
                    if p[48:60]==BitArray("0x000") and p[60:64]!=BitArray("0x0"):
                        if j in key3:
                            key3_.append(j)
                            flag3_=1
                            
                # Matching the pattern with state 3 for 4th faulty ciphertexts
                if flag0_==1 and flag1_==1 and flag2_==1 and flag3_==1:
                    p4 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[4] ^ k ^ self.princeObj.RC[11], inverse=False)), inverse=False)
                    flag0__=0; flag1__=0; flag2__=0; flag3__=0
                    key0__=[]; key1__=[]; key2__=[]; key3__=[]
                    for j in range(2**16):
                        m = BitArray("0x"+"%04x"%j+"%04x"%j+"%04x"%j+"%04x"%j)
                        p0_ = self.princeObj.mPrime(self.princeObj.substitution(p0 ^ self.princeObj.RC[10] ^ m, inverse=False))
                        p4_ = self.princeObj.mPrime(self.princeObj.substitution(p4 ^ self.princeObj.RC[10] ^ m, inverse=False))
                        p = p0_ ^ p4_
                        if p[0:16]==BitArray("0x0000"):
                            if j in key0_:
                                key0__.append(j)
                                flag0__=1
                        if p[16:20]==BitArray("0x0") and p[20:24]!=BitArray("0x0") and p[24:32] == BitArray("0x00"):
                            if j in key1_:
                                key1__.append(j)
                                flag1__=1
                        if p[32:40]==BitArray("0x00") and p[40:44]!=BitArray("0x0") and p[44:48] == BitArray("0x0"):
                            if j in key2_:
                                key2__.append(j)
                                flag2__=1
                        if p[48:60]==BitArray("0x000") and p[60:64]!=BitArray("0x0"):
                            if j in key3_:
                                key3__.append(j)
                                flag3__=1                    
                
                    #Remove the key from k0' xor k1  if no satisfying k1 was found
                    if flag0__==1 and flag1__==1 and flag2__==1 and flag3__==1:
                        k0123.append(k)
                        K1_0th_col.append(key0__)
                        K1_1st_col.append(key1__)
                        K1_2nd_col.append(key2__)
                        K1_3rd_col.append(key3__)
                
        
        return k0123, K1_0th_col, K1_1st_col, K1_2nd_col, K1_3rd_col
    
    # Function to reduce key-space of k0' xor k1 and k1 by matching the pattern with state 1 for the faulty ciphertexts
    def check_pattern_state_1(self, k0Prime_xor_k1, K1_0th_col, K1_1st_col, K1_2nd_col, K1_3rd_col):
        k0Prime_xor_k1_= []; k1_ = []
        for i in range(len(k0Prime_xor_k1)):
            k = k0Prime_xor_k1[i]
            for k0 in K1_0th_col[i]:
                for k1 in K1_1st_col[i]:
                    for k2 in K1_2nd_col[i]:
                        for k3 in K1_3rd_col[i]:
                            K_1 = 2**48 * k0 + 2**32 * k1 + 2**16 * k2 + k3
                            K_1 = BitArray(hex="%016x"%K_1)
                            p0_state4 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[0] ^ k ^ self.princeObj.RC[11], inverse=False)), inverse=False)
                            p0_state2 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p0_state4 ^ K_1 ^ self.princeObj.RC[10], inverse=False)), inverse =False)
                            if not self.v2:
                                p0_state1 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p0_state2 ^ K_1 ^ self.princeObj.RC[9])), inverse=False)
                            else:
                                p0_state1 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p0_state2 ^ k ^ self.princeObj.RC[9])), inverse=False)
                                
                            p1_state4 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[1] ^ k ^ self.princeObj.RC[11], inverse=False)), inverse=False)
                            p1_state2 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p1_state4 ^ K_1 ^ self.princeObj.RC[10], inverse=False)), inverse =False)
                            if not self.v2:
                                p1_state1 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p1_state2 ^ K_1 ^ self.princeObj.RC[9])), inverse=False)
                            else:
                                p1_state1 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p1_state2 ^ k ^ self.princeObj.RC[9])), inverse=False)
                            p1 = p0_state1 ^ p1_state1
                            
                            # Matching the pattern with state 1 for 1st faulty ciphertexts
                            if p1[0:4]==BitArray("0x1") and p1[4:64]==BitArray(hex="%015x"%0):
                                p2_state4 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[2] ^ k ^ self.princeObj.RC[11], inverse=False)), inverse=False)
                                p2_state2 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p2_state4 ^ K_1 ^ self.princeObj.RC[10], inverse=False)), inverse =False)
                                if not self.v2:
                                    p2_state1 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p2_state2 ^ K_1 ^ self.princeObj.RC[9])), inverse=False)
                                else:
                                    p2_state1 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p2_state2 ^ k ^ self.princeObj.RC[9])), inverse=False)
                                p2  = p0_state1 ^ p2_state1
                                
                                # Matching the pattern with state 1 for 2nd faulty ciphertexts
                                if p2[0:4]==BitArray("0x2") and p2[4:64]==BitArray(hex="%015x"%0):
                                    p3_state4 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[3] ^ k ^ self.princeObj.RC[11], inverse=False)), inverse=False)
                                    p3_state2 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p3_state4 ^ K_1 ^ self.princeObj.RC[10], inverse=False)), inverse =False)
                                    if not self.v2:
                                        p3_state1 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p3_state2 ^ K_1 ^ self.princeObj.RC[9])), inverse=False)
                                    else:
                                        p3_state1 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p3_state2 ^ k ^ self.princeObj.RC[9])), inverse=False)
                                    p3  = p0_state1 ^ p3_state1
                                    
                                    # Matching the pattern with state 1 for 3rd faulty ciphertexts
                                    if p3[0:4]==BitArray("0x4") and p3[4:64]==BitArray(hex="%015x"%0):
                                        p4_state4 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(self.cipherTexts[4] ^ k ^ self.princeObj.RC[11], inverse=False)), inverse=False)
                                        p4_state2 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p4_state4 ^ K_1 ^ self.princeObj.RC[10], inverse=False)), inverse =False)
                                        if not self.v2:
                                            p4_state1 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p4_state2 ^ K_1 ^ self.princeObj.RC[9])), inverse=False)
                                        else:
                                            p4_state1 = self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(p4_state2 ^ k ^ self.princeObj.RC[9])), inverse=False)
                                        p4  = p0_state1 ^ p4_state1
                                        
                                        # Matching the pattern with state 1 for 4th faulty ciphertexts
                                        if p4[0:4]==BitArray("0x8") and p4[4:64]==BitArray(hex="%015x"%0):
                                            k0Prime_xor_k1_.append(k)
                                            k1_.append(K_1)
        return k0Prime_xor_k1_, k1_
    
    def launch_attack(self, reflection=0):
        if not self.v2:
            print ("****************************** Launching Slow Diffusion Attack on PRINCE ******************************\n"+103*"*")
        else:
            print ("****************************** Launching Slow Diffusion Attack on PRINCE v2 ******************************\n"+106*"*")
        print("Before Attack: =======================> ")
        self.princeObj.printKeys()
        faultyNibble = 0
        print("Faulty Nibble: \t",faultyNibble,"\t (Fixed here)") 
        self.generate_faulty_cipherTexts(reflection)             # Calling the function to generate ciphertexts
        K_0th_col, K_1st_col, K_2nd_col, K_3rd_col = self.check_pattern_state_5_ciphertext_1()          # Calling the function to refine the key guess for k0' xor k1
        for j in range(2,5):
            K_0th_col, K_1st_col, K_2nd_col, K_3rd_col = self.check_pattern_state_5_ciphertext_j(j, K_0th_col, K_1st_col, K_2nd_col, K_3rd_col)          # Calling the function to further refine the key guess for k0' xor k1
        k0Prime_xor_k1 = self.merge(K_0th_col, K_1st_col, K_2nd_col, K_3rd_col) # Calling the funciton to merge the 4 sets of  key guesses of each column
        k0Prime_xor_k1, K1_0th_col, K1_1st_col, K1_2nd_col, K1_3rd_col = self.check_pattern_state_3(k0Prime_xor_k1)  # Calling the function to refine the key guess for k0' xor k1 and k1
        flag = 0
        if  len(k0Prime_xor_k1)!=1:
            flag = 1
        else:
            for i in range(len(k0Prime_xor_k1)):
                if (len(K1_0th_col[i])!=1 or len(K1_1st_col[i])!=1 or len(K1_2nd_col[i])!=1 or len(K1_3rd_col[i])!=1):
                    flag = 1
                    break
        if flag:
            k0Prime_xor_k1, k1 = self.check_pattern_state_1(k0Prime_xor_k1, K1_0th_col, K1_1st_col, K1_2nd_col, K1_3rd_col) # Calling the function to further refine the key guess for k0' xor k1 and k1
        # Getting the value of k0' xor k1
        k0Prime_xor_k1 = k0Prime_xor_k1[0]
        # Getting the value of k1
        if flag:
            k1 = k1[0]
        else:
            k1 = 2**48 * K1_0th_col[0][0] + 2**32 * K1_1st_col[0][0] + 2**16 * K1_2nd_col[0][0] + K1_3rd_col[0][0]
            k1 = BitArray(hex="%016x"%k1)
        if not self.v2:
            k0Prime = k1 ^ k0Prime_xor_k1
        print("After Attack: =======================> ")
        if not self.v2:
            print("K1: \t",k1) 
            print("K0-Prime: \t",k0Prime) 
            print("K1 ^ K0-Prime: \t",k0Prime_xor_k1)
        else:
            print("K0: \t",k1) 
            print("K1: \t",k0Prime_xor_k1)

        

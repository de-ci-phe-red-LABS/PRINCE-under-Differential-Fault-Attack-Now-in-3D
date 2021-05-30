#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
from bitstring import BitArray
from PRINCE import PRINCE
from PRINCE_v2 import PRINCE_v2

ALPHA = BitArray("0xc0ac29b7c97c50dd")
BETA = BitArray("0x3f84d5b5b5470917")

class IntegralAttack:
    
    def __init__(self, plainText, key, v2=False):
        self.plainText = plainText
        self.v2 = v2                                  # Variable for PRINCE v2
        if not self.v2:
            self.princeObj = PRINCE(key)
        else:
            self.princeObj = PRINCE_v2(key)
        self.faultyNibble = random.randint(0,15)      # Fault position
        self.cipherTexts = []
    
    # Function to generate all ciphertexts for Integral attack    
    def generate_faulty_cipherTexts(self, reflection=0):
        for i in range(16):
            faultValue = BitArray("0x"+"%016x"%0)
            faultValue[self.faultyNibble*4 : self.faultyNibble*4+4] = i
            if not reflection:
                if not self.v2:
                    data = self.plainText ^ self.princeObj.k0 ^ self.princeObj.k1 ^ self.princeObj.RC[0]
                else:
                    data = self.plainText ^ self.princeObj.k0 ^ self.princeObj.RC[0]
                for idx in (1,2,3,4,5):
                    data = self.princeObj.forwardRound(data, idx)
                data = self.princeObj.middleRound(data)
                for idx in (6,7,8,9,10):
                    if (idx!=7):
                        data = self.princeObj.backwardRound(data, idx)
                    else:
                        data ^= self.princeObj.k1 ^ self.princeObj.RC[idx]
                        data = self.princeObj.shiftRows(data, inverse=True)
                        data = self.princeObj.mPrime(data)
                        data ^= faultValue                                     # Fault injection
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
                    if (idx!=4):
                        data = self.princeObj.forwardRound(data, idx)
                    else:
                        data = self.princeObj.substitution(data, inverse=False)
                        data ^= faultValue                                     # Fault injection
                        data = self.princeObj.mPrime(data)
                        data = self.princeObj.shiftRows(data, inverse=False)
                        if not self.v2:
                            data ^= self.princeObj.RC[idx] ^ self.princeObj.k1
                        else:
                            data ^= self.princeObj.RC[idx] ^ self.princeObj.k0
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
            
        
    # Function to check the balanced property of the nibbles at state 13        
    def check_balanced_property_state_13(self):
        k00=[]; k01=[]; k02=[]; k03=[]; k10=[]; k11=[]; k12=[]; k13=[]; k20=[]; k21=[]; k22=[]; k23=[]; k30=[]; k31=[]; k32=[]; k33=[]
        for i in range(16):
            final="0x0000000000000000"                    #  BALANCED property check for each nibble
            for j in self.cipherTexts:
                j = j ^ BitArray("0x"+"%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+ "%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+ "%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i) ^ self.princeObj.RC[11]
                j = self.princeObj.substitution(j, inverse=False)
                final=final^j
            if 8*final[0]+4*final[1]+2*final[2]+final[3]==0:     # Nibble 0
                k00.append(i)
            if 8*final[4]+4*final[5]+2*final[6]+final[7]==0:     # Nibble 1
                k01.append(i)
            if 8*final[8]+4*final[9]+2*final[10]+final[11]==0:   # Nibble 2
                k02.append(i)
            if 8*final[12]+4*final[13]+2*final[14]+final[15]==0: # Nibble 3
                k03.append(i) 
            if 8*final[16]+4*final[17]+2*final[18]+final[19]==0: # Nibble 4
                k10.append(i)
            if 8*final[20]+4*final[21]+2*final[22]+final[23]==0: # Nibble 5
                k11.append(i)
            if 8*final[24]+4*final[25]+2*final[26]+final[27]==0: # Nibble 6
                k12.append(i)
            if 8*final[29]+4*final[29]+2*final[30]+final[31]==0: # Nibble 7
                k13.append(i) 
            if 8*final[32]+4*final[33]+2*final[34]+final[35]==0: # Nibble 8
                k20.append(i)
            if 8*final[36]+4*final[37]+2*final[38]+final[39]==0: # Nibble 9
                k21.append(i)
            if 8*final[40]+4*final[41]+2*final[42]+final[43]==0: # Nibble 10
                k22.append(i)
            if 8*final[44]+4*final[45]+2*final[46]+final[47]==0: # Nibble 11
                k23.append(i) 
            if 8*final[48]+4*final[49]+2*final[50]+final[51]==0: # Nibble 12
                k30.append(i)
            if 8*final[52]+4*final[53]+2*final[54]+final[55]==0: # Nibble 13
                k31.append(i)
            if 8*final[56]+4*final[57]+2*final[58]+final[59]==0: # Nibble 14
                k32.append(i)
            if 8*final[60]+4*final[61]+2*final[62]+final[63]==0: # Nibble 15
                k33.append(i) 
                
        K_0th_col=[]; K_1st_col=[]; K_2nd_col=[]; K_3rd_col=[]
        
        for i in k00:      # Combining first 4 nibbles for 0th column          
            for j in k01:
                for k in k02:
                    for l in k03:
                        K_0th_col.append(BitArray("0x"+"%01x"%i+"%01x"%j+"%01x"%k+"%01x"%l+"%012x"%0 ))
            
        for i in k10:      # Combining  next 4 nibbles for 1st column  
            for j in k11:
                for k in k12:
                    for l in k13:
                        K_1st_col.append(BitArray("0x"+"%05x"%i+"%01x"%j+"%01x"%k+"%01x"%l+"%08x"%0 ))
    
        for i in k20:      # Combining  next 4 nibbles for 2nd column 
            for j in k21:
                for k in k22:
                    for l in k23:
                        K_2nd_col.append(BitArray("0x"+"%09x"%i+"%01x"%j+"%01x"%k+"%01x"%l+"%04x"%0 ))
    
        for i in k30:      # Combining  next 4 nibbles for 3rd column 
            for j in k31:
                for k in k32:
                    for l in k33:
                        K_3rd_col.append(BitArray("0x"+"%013x"%i+"%01x"%j+"%01x"%k+"%01x"%l))
                        
        return K_0th_col, K_1st_col, K_2nd_col, K_3rd_col
    
    # Function to check the correct pattern at state 12 and thus to reduce the key-space
    def check_pattern_state_12(self, K_0th_col, K_1st_col, K_2nd_col, K_3rd_col):
        # Columnwise Pattern in State 13 for each of the 16 different faut positions
        Pattern0=[[6,6,6,5],[5,6,6,5],[6,6,6,5],[5,6,6,6],[6,6,5,6],[6,7,5,5],[6,6,6,6],[6,5,5,5],[7,6,5,6],[6,5,6,7],[5,6,5,6],[6,5,6,6],[5,5,7,6],[6,6,6,6],[5,5,6,6],[6,6,6,6]];
        Pattern1=[[6,5,6,6],[6,6,6,6],[5,5,6,6],[5,6,7,5],[5,6,6,6],[6,6,6,5],[6,7,6,5],[6,6,6,6],[6,6,5,6],[6,6,6,6],[7,6,5,6],[5,6,5,5],[5,6,6,6],[6,5,5,7],[6,5,6,5],[6,5,5,6]];
        Pattern2=[[5,5,6,7],[7,6,5,5],[6,6,6,6],[5,6,6,6],[6,6,5,6],[6,5,6,6],[6,6,6,5],[5,6,7,6],[5,5,6,5],[6,6,5,5],[6,6,6,6],[6,6,6,6],[6,5,5,6],[6,5,6,6],[6,7,6,5],[5,6,5,6]];
        Pattern3=[[6,5,6,6],[6,6,5,6],[5,7,6,5],[6,6,5,6],[7,5,5,6],[6,6,6,5],[5,5,5,6],[5,6,6,6],[6,6,6,6],[6,5,6,5],[5,6,6,5],[6,5,6,7],[6,6,6,6],[6,6,5,5],[6,6,6,6],[5,6,7,6]];
        
        # Check for quasi-active nibbles in 0th column of Key.
        faulty_nibble0=[]
        for i in K_0th_col:    
            e4=[]; e5=[]; e6=[]; e7=[]
            for j in self.cipherTexts:
                j = j ^ i ^ self.princeObj.RC[11]
                j = self.princeObj.substitution(j, inverse=False)
                j = self.princeObj.mPrime(j)
                if j[0:4] not in e4:
                    e4.append(j[0:4])
                if j[4:8] not in e5:
                    e5.append(j[4:8])
                if j[8:12] not in e6:
                    e6.append(j[8:12])
                if j[12:16] not in e7:
                    e7.append(j[12:16])
            for k in range(0,16):
                if ([len(e4),len(e5),len(e6),len(e7)] == Pattern0[k]) and (k not in faulty_nibble0) :
                    faulty_nibble0.append([k,i])
                        
        # Check for quasi-active nibbles in 1st column of Key.
        faulty_nibble1=[]
        for i in K_1st_col:
            e4=[]; e5=[]; e6=[]; e7=[]
            for j in self.cipherTexts:
                j = j ^ i ^ self.princeObj.RC[11]
                j = self.princeObj.substitution(j, inverse=False)
                j = self.princeObj.mPrime(j)          
                if j[16:20] not in e4:
                    e4.append(j[16:20])
                if j[20:24] not in e5:
                    e5.append(j[20:24])
                if j[24:28] not in e6:
                    e6.append(j[24:28])
                if j[28:32] not in e7:
                    e7.append(j[28:32])
            for k in range(0,16):
                if ([len(e4),len(e5),len(e6),len(e7)] == Pattern1[k]) and (k not in faulty_nibble1) :
                    faulty_nibble1.append([k,i])
                        
        # Check for quasi-active nibbles in 2nd column of Key.
        faulty_nibble2=[]
        for i in K_2nd_col:
            e4=[]; e5=[]; e6=[]; e7=[]
            for j in self.cipherTexts:
                j = j ^ i ^ self.princeObj.RC[11]
                j = self.princeObj.substitution(j, inverse=False)
                j = self.princeObj.mPrime(j)             
                if j[32:36] not in e4:
                    e4.append(j[32:36])
                if j[36:40] not in e5:
                    e5.append(j[36:40])
                if j[40:44] not in e6:
                    e6.append(j[40:44])
                if j[44:48] not in e7:
                    e7.append(j[44:48])
            for k in range(0,16):
                if ([len(e4),len(e5),len(e6),len(e7)] == Pattern2[k]) and (k not in faulty_nibble2) :
                    faulty_nibble2.append([k,i])
                    
        # Check for quasi-active nibbles in 3rd column of Key.
        faulty_nibble3=[]
        for i in K_3rd_col:
            e4=[]; e5=[]; e6=[]; e7=[]
            for j in self.cipherTexts:
                j = j ^ i ^ self.princeObj.RC[11]
                j = self.princeObj.substitution(j, inverse=False)
                j = self.princeObj.mPrime(j)            
                if j[48:52] not in e4:
                    e4.append(j[48:52])
                if j[52:56] not in e5:
                    e5.append(j[52:56])
                if j[56:60] not in e6:
                    e6.append(j[56:60])
                if j[60:64] not in e7:
                    e7.append(j[60:64])
            for k in range(0,16):
                if ([len(e4),len(e5),len(e6),len(e7)] == Pattern3[k]) and (k not in faulty_nibble3) :
                    faulty_nibble3.append([k,i])
                    
        # Combining all key guesses.
        faultyNibble=[]
        k0Prime_xor_k1=[]
        for i in faulty_nibble0:
            for j in faulty_nibble1:
                for k in faulty_nibble2:
                    for l in faulty_nibble3:
                        if i[0]==j[0] and j[0]==k[0] and k[0]==l[0]:
                            faultyNibble.append(i[0])
                            k0Prime_xor_k1.append(i[1]|j[1]|k[1]|l[1])
                                                    
        return faultyNibble, k0Prime_xor_k1
    
    # Function to check the pattern at State 8 and find the fault position
    def check_pattern_state_8(self, faultyNibble, k0Prime_xor_k1):
        faultyNibble_=[]; k0Prime_xor_k1_ = []; k1__=[]
        for ind in range(len(faultyNibble)):
            fNibble = faultyNibble[ind]
            if fNibble in [0,13,10,7]:  # to distribute the faulty nibble to faulty column 
                faulty_column=0
            if fNibble in [4,1,14,11]:
                faulty_column=1
            if fNibble in [8,5,2,15]:
                faulty_column=2
            if fNibble in [12,9,6,3]:
                faulty_column=3
                
            # Different Quasi-active nibble states for fault in each of the four columns
            Pattern_S8 = [[[8,1,1,1],[1,8,1,1],[1,1,8,1],[1,1,1,8]], 
                          [[1,1,1,8],[8,1,1,1],[1,8,1,1],[1,1,8,1]],
                          [[1,1,8,1],[1,1,1,8],[8,1,1,1],[1,8,1,1]],
                          [[1,8,1,1],[1,1,8,1],[1,1,1,8],[8,1,1,1]]];
            
            # Now as we know the fault position we can go back one more round and store the values of State 11
            state_11=[]
            for j in self.cipherTexts:
                state_11.append(self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(j ^ k0Prime_xor_k1[ind] ^ self.princeObj.RC[11], inverse=False)),inverse=False))
                
            # Seperating k1 from K1^K0' and going back till State 8 and matching the pattern there based on faulty nibble.
            K1_0th_col=[]; K1_1st_col=[]; K1_2nd_col=[]; K1_3rd_col=[]
            flag0=0; flag1=0; flag2=0; flag3=0;
            for k in range(2**16):
                e0=set(); e1=set(); e2=set(); e3=set(); e4=set(); e5=set(); e6=set(); e7=set(); e8=set(); e9=set(); e10=set(); e11=set(); e12=set(); e13=set(); e14=set(); e15=set()
                for j in state_11:
                    j1 = j ^ BitArray("0x"+  "%04x" % k + "%04x" % k +"%04x" % k +"%04x" % k ) ^ self.princeObj.RC[10]
                    j1 = self.princeObj.mPrime(self.princeObj.substitution(j1, inverse=False))
                    
                    m=0  # Storing 0th column's distinct values in the sets 
                    e0.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
                    e1.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
                    e2.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
                    e3.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])
                        
                    m=4 # Storing 1st column's distinct values in the sets
                    e4.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
                    e5.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
                    e6.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
                    e7.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])
                        
                    m=8 # Storing 2nd column's distinct values in the sets
                    e8.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
                    e9.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
                    e10.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
                    e11.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])
        
                    m=12 # Storing 3rd column's distinct values in the sets
                    e12.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
                    e13.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
                    e14.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
                    e15.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])             
        
                # Checking if the pattern matches or not
                if [len(e0),len(e1),len(e2),len(e3)]==Pattern_S8[faulty_column][0]:
                    K1_0th_col.append(k)
                    flag0 = 1
                if [len(e4),len(e5),len(e6),len(e7)]==Pattern_S8[faulty_column][1]:
                    K1_1st_col.append(k)
                    flag1 = 1
                if [len(e8),len(e9),len(e10),len(e11)]==Pattern_S8[faulty_column][2]:
                    K1_2nd_col.append(k)
                    flag2 = 1
                if [len(e12),len(e13),len(e14),len(e15)]==Pattern_S8[faulty_column][3]:
                    K1_3rd_col.append(k)
                    flag3 = 1
            
            if flag0==1 and flag1==1 and flag2==1 and flag3==1:
                faultyNibble_.append(fNibble)
                k0Prime_xor_k1_.append(k0Prime_xor_k1[ind])
                k1_ = []
                for K1_0 in K1_0th_col:
                    for K1_1 in K1_1st_col:
                        for K1_2 in K1_2nd_col:
                            for K1_3 in K1_3rd_col:
                                k1 = 2**48 * K1_0 + 2**32 * K1_1 + 2**16 * K1_2 + K1_3
                                k1 = BitArray(hex="%016x"%k1)
                                k1_.append(k1)
                k1__.append(k1_)
        
        return faultyNibble_, k0Prime_xor_k1_, k1__
    
    # Function to check the pattern at State 4 and find the fault position
    def check_pattern_state_4(self, faultyNibble, k0Prime_xor_k1, k1):
        faultyNibble_=[]; k0Prime_xor_k1_ = []; k1__=[]
        for ind in range(len(faultyNibble)):
            fNibble = faultyNibble[ind]
            faultyNibble_row = fNibble%4
            faultyNibble_col = int(fNibble/4)
                
            # Different Quasi-active nibble states for fault in each nibble
            Pattern_S4 = [[1 for i in range(4)] for j in range(4)]
            Pattern_S4[faultyNibble_col+faultyNibble_row][faultyNibble_row] = 16
            
            # Now as we know the fault position we can go back one more round and store the values of State 11
            state_11=[]
            for j in self.cipherTexts:
                state_11.append(self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(j ^ k0Prime_xor_k1[ind] ^ self.princeObj.RC[11], inverse=False)),inverse=False))
                
            # Seperating k1 from K1^K0' and going back till State 4 and matching the pattern there based on faulty nibble.
            flag = 0; k1_ = []
            for k in k1[ind]:
                state_7=[]
                for j in state_11:
                    state_7.append(self.princeObj.shiftRows(self.princeObj.mPrime(self.princeObj.substitution(j ^ k ^ self.princeObj.RC[10], inverse=False)),inverse=False))
                e0=set(); e1=set(); e2=set(); e3=set(); e4=set(); e5=set(); e6=set(); e7=set(); e8=set(); e9=set(); e10=set(); e11=set(); e12=set(); e13=set(); e14=set(); e15=set()
                for j in state_7:
                    if not self.v2:
                        j1 = j ^ BitArray("0x"+  "%04x" % k + "%04x" % k +"%04x" % k +"%04x" % k ) ^ self.princeObj.RC[9]
                    else:
                        j1 = j ^ BitArray("0x"+  "%04x" % k0Prime_xor_k1[ind] + "%04x" % k0Prime_xor_k1[ind] +"%04x" % k0Prime_xor_k1[ind] +"%04x" % k0Prime_xor_k1[ind] ) ^ self.princeObj.RC[9]
                    j1 = self.princeObj.mPrime(self.princeObj.substitution(j1, inverse=False))
                
                    m=0  # Storing 0th column's distinct values in the sets 
                    e0.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
                    e1.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
                    e2.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
                    e3.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])
                        
                    m=4 # Storing 1st column's distinct values in the sets
                    e4.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
                    e5.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
                    e6.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
                    e7.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])
                        
                    m=8 # Storing 2nd column's distinct values in the sets
                    e8.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
                    e9.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
                    e10.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
                    e11.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])
        
                    m=12 # Storing 3rd column's distinct values in the sets
                    e12.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
                    e13.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
                    e14.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
                    e15.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])             
            
                # Checking if the pattern matches or not
                if [len(e0),len(e1),len(e2),len(e3)]==Pattern_S4[0] and [len(e4),len(e5),len(e6),len(e7)]==Pattern_S4[1] and [len(e8),len(e9),len(e10),len(e11)]==Pattern_S4[2] and [len(e12),len(e13),len(e14),len(e15)]==Pattern_S4[3]:
                    k1_.append(k)
                    flag = 1
                    
            if flag==1:
                faultyNibble_.append(fNibble)
                k0Prime_xor_k1_.append(k0Prime_xor_k1[ind])
                k1__.append(k1_)
                
        return faultyNibble_, k0Prime_xor_k1_, k1__
        
    def launch_attack(self, reflection=0):
        if not self.v2:
            print ("****************************** Launching Integral Attack on PRINCE ******************************\n"+97*"*")
        else:
            print ("****************************** Launching Integral Attack on PRINCE v2 ******************************\n"+100*"*")
        print("Before Attack: =======================> ")
        self.princeObj.printKeys()
        self.generate_faulty_cipherTexts(reflection)             # Calling the function to generate ciphertexts
        K_0th_col, K_1st_col, K_2nd_col, K_3rd_col = self.check_balanced_property_state_13()             # Calling the function to get the values of reduced possible columnwise key guesses of K0' xor K1
        faultyNibble, k0Prime_xor_k1 = self.check_pattern_state_12(K_0th_col, K_1st_col, K_2nd_col, K_3rd_col)        # Calling the function to get the exact fault position and value of K0' xor K1
        faultyNibble, k0Prime_xor_k1, k1 = self.check_pattern_state_8(faultyNibble, k0Prime_xor_k1)           # Calling the function to return us the value of K1 based on pattren of state 8
        flag = 0
        if  len(k0Prime_xor_k1)!=1:
            flag = 1
        else:
            for i in range(len(k0Prime_xor_k1)):
                if len(k1[i])!=1:
                    flag = 1
                    break
        if flag:
            faultyNibble, k0Prime_xor_k1, k1 = self.check_pattern_state_4(faultyNibble, k0Prime_xor_k1, k1)
        faultyNibble = faultyNibble[0]
        k0Prime_xor_k1 = k0Prime_xor_k1[0]
        k1 = k1[0][0]
        if not self.v2:
            k0Prime = k1 ^ k0Prime_xor_k1
        print("After Attack: =======================> ")
        print("Faulty Nibble: \t",faultyNibble) 
        if not self.v2:
            print("K1: \t",k1) 
            print("K0-Prime: \t",k0Prime) 
            print("K1 ^ K0-Prime: \t",k0Prime_xor_k1)
        else:
            print("K0: \t",k1) 
            print("K1: \t",k0Prime_xor_k1)

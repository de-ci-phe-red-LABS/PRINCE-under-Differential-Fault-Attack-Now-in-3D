#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bitstring import BitArray

ALPHA = BitArray("0xc0ac29b7c97c50dd")
BETA = BitArray("0x3f84d5b5b5470917")

class PRINCE_v2:
    
    def __init__(self, key):
        self.key = key
        self.k0 = key[0:64]
        self.k1 = key[64:128]
        self.RC = (BitArray(hex = '0x0000000000000000'), 
                   BitArray(hex = '0x13198a2e03707344'),
                   BitArray(hex = '0xa4093822299f31d0'),
                   BitArray(hex = '0x082efa98ec4e6c89'),
                   BitArray(hex = '0x452821e638d01377'),
                   BitArray(hex = '0xbe5466cf34e90c6c'),
                   BitArray(hex = '0x7ef84f78fd955cb1'),
                   BitArray(hex = '0x7aacf4538d971a60'),
                   BitArray(hex = '0xc882d32f25323c54'),
                   BitArray(hex = '0x9b8ded979cd838c7'),
                   BitArray(hex = '0xd3b5a399ca0c2399'),
                   BitArray(hex = '0x3f84d5b5b5470917'))
        self.sbox = ('0xb', '0xf', '0x3', '0x2', '0xa', '0xc', '0x9', '0x1',  
                     '0x6', '0x7', '0x8', '0x0', '0xe', '0x5', '0xd', '0x4')
        self.invSbox = ('0xb', '0x7', '0x3', '0x2', '0xf', '0xd', '0x8', '0x9', 
                        '0xa', '0x6', '0x4', '0x0', '0x5', '0xe', '0xc', '0x1')
        
    def substitution(self, data, inverse=False):
        ret = BitArray()
        for nibble in data.cut(4):
            if not inverse:
                ret.append(self.sbox[int(nibble.hex, 16)])
            else:
                ret.append(self.invSbox[int(nibble.hex, 16)])
        return ret
    
    def shiftRows(self, data, inverse=False):
        ret = BitArray(length = 64)
        idx = 0
        for nibble in data.cut(4):
            ret[idx * 4:(idx + 1) * 4] = nibble
            if not inverse:
                idx = (idx + 13) % 16
            else:
                idx = (idx +  5) % 16
        return ret
    
    def m0(self, data):
        ret = BitArray(length = 16)
        ret[ 0] = data[4] ^ data[ 8] ^ data[12]
        ret[ 1] = data[1] ^ data[ 9] ^ data[13]
        ret[ 2] = data[2] ^ data[ 6] ^ data[14]
        ret[ 3] = data[3] ^ data[ 7] ^ data[11]
        ret[ 4] = data[0] ^ data[ 4] ^ data[ 8]
        ret[ 5] = data[5] ^ data[ 9] ^ data[13]
        ret[ 6] = data[2] ^ data[10] ^ data[14]
        ret[ 7] = data[3] ^ data[ 7] ^ data[15]
        ret[ 8] = data[0] ^ data[ 4] ^ data[12]
        ret[ 9] = data[1] ^ data[ 5] ^ data[ 9]
        ret[10] = data[6] ^ data[10] ^ data[14]
        ret[11] = data[3] ^ data[11] ^ data[15]
        ret[12] = data[0] ^ data[ 8] ^ data[12]
        ret[13] = data[1] ^ data[ 5] ^ data[13]
        ret[14] = data[2] ^ data[ 6] ^ data[10]
        ret[15] = data[7] ^ data[11] ^ data[15]
        return ret
    
    def m1(self, data):
        ret = BitArray(length = 16)
        ret[ 0] = data[0] ^ data[ 4] ^ data[ 8]
        ret[ 1] = data[5] ^ data[ 9] ^ data[13]
        ret[ 2] = data[2] ^ data[10] ^ data[14]
        ret[ 3] = data[3] ^ data[ 7] ^ data[15]
        ret[ 4] = data[0] ^ data[ 4] ^ data[12]
        ret[ 5] = data[1] ^ data[ 5] ^ data[ 9]
        ret[ 6] = data[6] ^ data[10] ^ data[14]
        ret[ 7] = data[3] ^ data[11] ^ data[15]
        ret[ 8] = data[0] ^ data[ 8] ^ data[12]
        ret[ 9] = data[1] ^ data[ 5] ^ data[13]
        ret[10] = data[2] ^ data[ 6] ^ data[10]
        ret[11] = data[7] ^ data[11] ^ data[15]
        ret[12] = data[4] ^ data[ 8] ^ data[12]
        ret[13] = data[1] ^ data[ 9] ^ data[13]
        ret[14] = data[2] ^ data[ 6] ^ data[14]
        ret[15] = data[3] ^ data[ 7] ^ data[11]
        return ret
    
    def mPrime(self, data):
        ret = BitArray(length = 64)
        ret[ 0:16] = self.m0(data[ 0:16])
        ret[16:32] = self.m1(data[16:32])
        ret[32:48] = self.m1(data[32:48])
        ret[48:64] = self.m0(data[48:64])
        return ret
        
    def forwardRound(self, data, idx):
        data = self.substitution(data, inverse=False)
        data = self.mPrime(data)
        data = self.shiftRows(data, inverse=False)
        data ^= self.RC[idx]
        if (idx % 2):
            data ^= self.k1
        else:
            data ^= self.k0
        return data
        
    def backwardRound(self, data, idx):
        if (idx % 2):
            data ^= self.k1
        else:
            data ^= self.k0
        data ^= self.RC[idx]
        data = self.shiftRows(data, inverse=True)
        data = self.mPrime(data)
        data = self.substitution(data, inverse=True)
        return data
    
    def middleRound(self, data):
        data = self.substitution(data, inverse=False)
        data ^= self.k0
        data = self.mPrime(data)
        data ^= self.k1 ^ self.RC[11]
        data = self.substitution(data, inverse=True)
        return data
        
    def princev2(self, data, decrypt=False):
        if decrypt:
            tmp = self.k0
            self.k0 = self.k1
            self.k1 = tmp
            self.k0 ^= BETA
            self.k1 ^= ALPHA
        data ^= self.k0 ^ self.RC[0]
        for idx in (1,2,3,4,5):
            data = self.forwardRound(data, idx)
        if decrypt:
            self.k1 ^= ALPHA ^ BETA 
        data = self.middleRound(data)
        if decrypt:
            self.k0 ^= ALPHA ^ BETA 
        for idx in (6,7,8,9,10):
            data = self.backwardRound(data, idx)
        data ^= self.k1 ^ self.RC[11]
        if decrypt:
            self.k0 ^= BETA ^ ALPHA ^ BETA
            self.k1 ^= ALPHA ^ ALPHA ^ BETA
            tmp = self.k0
            self.k0 = self.k1
            self.k1 = tmp            
        return data
    
    def encrypt(self, plainText):
        data = self.princev2(plainText, decrypt=False)
        return data
    
    def decrypt(self, cipherText):
        data = self.princev2(cipherText, decrypt=True)
        return data
    
    def printKeys(self):
        print("K0: \t",self.k0) 
        print("K1: \t",self.k1)
#!/usr/bin/env python
# coding: utf-8

# In[1]:


# ----------------------------------- Prince implementation --------------------------------------------------

from bitstring import BitArray

#Round Constants

RC = (BitArray(hex = '0x0000000000000000'),  
          BitArray(hex = '0x13198a2e03707344'),
          BitArray(hex = '0xa4093822299f31d0'),
          BitArray(hex = '0x082efa98ec4e6c89'),
          BitArray(hex = '0x452821e638d01377'),
          BitArray(hex = '0xbe5466cf34e90c6c'),
          BitArray(hex = '0x7ef84f78fd955cb1'),
          BitArray(hex = '0x85840851f1ac43aa'),
          BitArray(hex = '0xc882d32f25323c54'),
          BitArray(hex = '0x64a51195e0e3610d'),
          BitArray(hex = '0xd3b5a399ca0c2399'),
          BitArray(hex = '0xc0ac29b7c97c50dd'))


#Sbox and inverse Sbox

S = ('0xb', '0xf', '0x3', '0x2', '0xa', '0xc', '0x9', '0x1',
     '0x6', '0x7', '0x8', '0x0', '0xe', '0x5', '0xd', '0x4')
sb=(0xb,0xf,3,2,10,12,9,1,6,7,8,0,14,5,13,4)

Sinv = ('0xb', '0x7', '0x3', '0x2', '0xf', '0xd', '0x8', '0x9', '0xa', '0x6', '0x4', '0x0', '0x5', '0xe', '0xc', '0x1')

def sbox(data, box):
    ret = BitArray()
    for nibble in data.cut(4):
        ret.append(box[int(nibble.hex, 16)])
    return ret

def m0( data):
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

def m1(data):
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

def shiftrows( data, inverse):
    ret = BitArray(length = 64)
    idx = 0
    for nibble in data.cut(4):
        ret[idx * 4:(idx + 1) * 4] = nibble
        if not inverse:
            idx = (idx + 13) % 16
        else:
            idx = (idx +  5) % 16
    return ret

def mprime( data):
    ret = BitArray(length = 64)
    ret[ 0:16] = m0(data[ 0:16])
    ret[16:32] = m1(data[16:32])
    ret[32:48] = m1(data[32:48])
    ret[48:64] = m0(data[48:64])
    return ret

def firstrounds( data, key):
    for idx in (1,2,3,4,5):
        data = sbox(data, S)
        data = mprime(data)
        data = shiftrows(data, inverse = False)
        data ^= RC[idx] ^ key
    return data

def lastrounds( data, key):
    for idx in (6,7,8,9,10):
        data ^= key ^ RC[idx]
        data = shiftrows(data, inverse = True)
        data = mprime(data)
        data = sbox(data, Sinv)
    return data

def princecore( data, key):
    data ^= key ^ RC[0]
    data = firstrounds(data, key)
    data = sbox(data, S)
    data = mprime(data)
    data = sbox(data, Sinv)
    data = lastrounds(data, key)
    return data ^ key ^ RC[11]

def outer( data, key, decrypt = False):
    k0 = key[0:64]
    k0prime = k0.copy()
    k0prime.ror(1)
    k0prime ^= k0 >> 63
    if decrypt:
        tmp = k0
        k0 = k0prime
        k0prime = tmp
    k1 = key[64:128]
    data = k0 ^ data                                # pre-whitening
    data = princecore(data, k1)
    return (data ^ k0prime)                  # post-whitening

def encrypt(plaintext, key):
    bitkey = BitArray(key)
    bittext = BitArray(plaintext)
    return outer(bittext, bitkey)

def decrypt(ciphertext, key):
    bitkey = BitArray(key)
    bitkey ^= "0x0000000000000000c0ac29b7c97c50dd"  # alpha padded with zero
    bittext = BitArray(ciphertext)
    return outer(bittext, bitkey, True)



# In[2]:


# ------------------------- Funciton to generate faulty ciphertexts ------------------------------------------

def Generate_faulty_ciphertexts():
    p=BitArray("0x0000000000000000")
    key=BitArray("0x12341234567cabff0b01034a0cde0aab")

    for i in range(16): 
            A =  BitArray("0x"+"%04x"%i+"%012x"%0)       # Fault value
            k0 = key[0:64]
            k0prime = k0.copy()
            k0prime.ror(1)
            k0prime ^= k0 >> 63
            k1 = key[64:128]
            data = k0 ^ p                                # pre-whitening
            data ^= k1 ^ RC[0]
            data = firstrounds(data, k1)
            data = sbox(data, S)
            data = mprime(data)
            data1 = sbox(data, Sinv)
            data2 = sbox(data, Sinv)
            for idx in (6,7,8,9,10):
                data2 ^= k1 ^ RC[idx]
                data1 ^= k1 ^ RC[idx]
                data2 = shiftrows(data2, inverse = True)
                data1 = shiftrows(data1, inverse = True)
                data2 = mprime(data2)
                data1 = mprime(data1)
                if idx==7:
                    data1 = data1 ^ A                   # Fault inductuon
                data2 = sbox(data2, Sinv)
                data1 = sbox(data1, Sinv)
            data2 =  data2 ^ k1 ^ RC[11]
            data1 =  data1 ^ k1 ^ RC[11]
            data2= (data2 ^ k0prime)
            data1= (data1 ^ k0prime) 
            c.append(data1)
    return c
    
    


# In[3]:


#------------------- Function to check for balanced property and inactivity -----------------------------------

def Check_Balanced_Property_State_13(c):
    k00=[]
    k01=[]
    k02=[]
    k03=[]
    k10=[]
    k11=[]
    k12=[]
    k13=[]
    k20=[]
    k21=[]
    k22=[]
    k23=[]
    k30=[]
    k31=[]
    k32=[]
    k33=[]
    for i in range(16):
        final="0x0000000000000000"                    #  BALANCED property check for each nibble
        for j in c:
            j = j^BitArray("0x"+"%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+ "%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i+ "%01x"%i+"%01x"%i+"%01x"%i+"%01x"%i)^ RC[11]
            j = sbox(j,S)
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
    K0=[]
    K1=[]
    K2=[]
    K3=[]
    
    for i in k00:      #Combining first 4 nibbles for 1st column          
        for j in k01:
            for k in k02:
                for l in k03:
                    K0.append(BitArray("0x"+"%01x"%i+"%01x"%j+"%01x"%k+"%01x"%l+"%012x"%0 ))
        
    for i in k10:      #Combining  next 4 nibbles for 2nd column  
        for j in k11:
            for k in k12:
                for l in k13:
                    K1.append(BitArray("0x"+"%05x"%i+"%01x"%j+"%01x"%k+"%01x"%l+"%08x"%0 ))

    for i in k20:      #Combining  next 4 nibbles for 3rd column 
        for j in k21:
            for k in k22:
                for l in k23:
                    K2.append(BitArray("0x"+"%09x"%i+"%01x"%j+"%01x"%k+"%01x"%l+"%04x"%0 ))

    for i in k30:      #Combining  next 4 nibbles for 4th column 
        for j in k31:
            for k in k32:
                for l in k33:
                    K3.append(BitArray("0x"+"%013x"%i+"%01x"%j+"%01x"%k+"%01x"%l))
                    
    return K0,K1,K2,K3


# In[4]:


#----------------- Function to check for Pattern in State 13 to get K0'_xor_K1 and faulty nibble  -----------------------------------

def Check_Pattern_State_13(K0,K1,K2,K3,c):
    
                          #Columnwise Pattern in State 13 for each of the 16 different faut positions

    Pattern0=[[6,6,6,5],[5,6,6,5],[6,6,6,5],[5,6,6,6],[6,6,5,6],[6,7,5,5],[6,6,6,6],[6,5,5,5],[7,6,5,6],[6,5,6,7],[5,6,5,6],[6,5,6,6],[5,5,7,6],[6,6,6,6],[5,5,6,6],[6,6,6,6]];
    Pattern1=[[6,5,6,6],[6,6,6,6],[5,5,6,6],[5,6,7,5],[5,6,6,6],[6,6,6,5],[6,7,6,5],[6,6,6,6],[6,6,5,6],[6,6,6,6],[7,6,5,6],[5,6,5,5],[5,6,6,6],[6,5,5,7],[6,5,6,5],[6,5,5,6]];
    Pattern2=[[5,5,6,7],[7,6,5,5],[6,6,6,6],[5,6,6,6],[6,6,5,6],[6,5,6,6],[6,6,6,5],[5,6,7,6],[5,5,6,5],[6,6,5,5],[6,6,6,6],[6,6,6,6],[6,5,5,6],[6,5,6,6],[6,7,6,5],[5,6,5,6]];
    Pattern3=[[6,5,6,6],[6,6,5,6],[5,7,6,5],[6,6,5,6],[7,5,5,6],[6,6,6,5],[5,5,5,6],[5,6,6,6],[6,6,6,6],[6,5,6,5],[5,6,6,5],[6,5,6,7],[6,6,6,6],[6,6,5,5],[6,6,6,6],[5,6,7,6]];
    
                           # Check for quasi-active nibbles in first column of Key.
    faulty_nibble0=[]
    K0F=[]
    for i in K0:

            e4=[]
            e5=[]
            e6=[]
            e7=[]
            for j in c:
                    j = j^i^ RC[11]
                    j = sbox(j,S)
                    j = mprime(j)
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
    
                            # Check for quasi-active nibbles in second column of Key.
    faulty_nibble1=[]
    K1F=[]
    for i in K1:
            e4=[]
            e5=[]
            e6=[]
            e7=[]
            for j in c:
                j = j^i^ RC[11]
                j = sbox(j,S)
                j = mprime(j)            
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
    
                          # Check for quasi-active nibbles in thirdcolumn of Key.
    faulty_nibble2=[]
    K2F=[]
    for i in K2:
            e4=[]
            e5=[]
            e6=[]
            e7=[]
            for j in c:
                j = j^i^ RC[11]
                j = sbox(j,S)
                j = mprime(j)               
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

                         # Check for quasi-active nibbles in fourth column of Key.
    faulty_nibble3=[]
    K3F=[]
    for i in K3:
            e4=[]
            e5=[]
            e6=[]
            e7=[]
            for j in c:
                j = j^i^ RC[11]
                j = sbox(j,S)
                j = mprime(j)               
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
    faulty_nibble=0
    K0prime_xor_k1=0
    for i in faulty_nibble0:
        for j in faulty_nibble1:
            for k in faulty_nibble2:
                for l in faulty_nibble3:
                    if i[0]==j[0] and j[0]==k[0] and k[0]==l[0]:
                        faulty_nibble=i[0]
                        K0prime_xor_k1=i[1]|j[1]|k[1]|l[1]
                                                
    return faulty_nibble,K0prime_xor_k1



                
    


# In[5]:


# ---------------- Function to go back to state 8 and check for the pattern of the faulty nibble -------------
def Check_Pattern_State_8(faulty_nibble,K0prime_xor_k1):
    
    if faulty_nibble in [0,13,10,7]:  # to ditribute the faulty nibble to faulty column 
        faulty_column=0
    if faulty_nibble in [4,1,14,11]:
        faulty_column=1
    if faulty_nibble in [8,5,2,15]:
        faulty_column=2
    if faulty_nibble in [12,9,6,3]:
        faulty_column=3
        
    
                    # Different Quasi-active nibble states for fault in each of the four columns
    Pattern_S8 = [ [[8,1,1,1],[1,8,1,1],[1,1,8,1],[1,1,1,8]],
               [[1,1,1,8],[8,1,1,1],[1,8,1,1],[1,1,8,1]],
               [[1,1,8,1],[1,1,1,8],[8,1,1,1],[1,8,1,1]],
               [[1,8,1,1],[1,1,8,1],[1,1,1,8],[8,1,1,1]]];

    # Now that we know the fault position we can go back one more round and store the values of State 11
    c_1=[]
    for j in c:
        c_1.append(shiftrows(mprime(sbox(j^K0prime_xor_k1^ RC[11],S)),inverse=False)^RC[10])
        
    # Seperating k1 from K1^K0' and going back till State 8 and matching the pattern there based on faulty nibble.
    K1_0=[]
    K1_1=[]
    K1_2=[]
    K1_3=[]
    for k in range(2**16):
        e0=set()
        e1=set()
        e2=set()
        e3=set()
        e4=set()
        e5=set()
        e6=set()
        e7=set()
        e8=set()
        e9=set()
        e10=set()
        e11=set()
        e12=set()
        e13=set()
        e14=set()
        e15=set()
        for j in c_1:
            p=c[0]
            j1=j^BitArray("0x"+  "%04x" % k + "%04x" % k +"%04x" % k +"%04x" % k )
            p1=p^BitArray("0x"+  "%04x" % k + "%04x" % k +"%04x" % k +"%04x" % k )
            j1 = sbox(j1,S)
            p1 = sbox(p1,S)
            j1 = mprime(j1)
            p1 = mprime(p1)
            j1=j1^p1  
            m=0  # storing first column's distinct values in the sets 
            e0.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
            e1.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
            e2.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
            e3.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])
                
            m=4 # storing second column's distinct values in the sets
            e4.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
            e5.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
            e6.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
            e7.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])
                
            m=8 # storing third column's distinct values in the sets
            e8.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
            e9.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
            e10.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
            e11.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])

            m=12 # storing fourth column's distinct values in the sets
            e12.add(8*j1[m*4:m*4+4][0]+4*j1[m*4:m*4+4][1]+2*j1[m*4:m*4+4][2]+j1[m*4:m*4+4][3])
            e13.add(8*j1[m*4+4:m*4+8][0]+4*j1[m*4+4:m*4+8][1]+2*j1[m*4+4:m*4+8][2]+j1[m*4+4:m*4+8][3])
            e14.add(8*j1[m*4+8:m*4+12][0]+4*j1[m*4+8:m*4+12][1]+2*j1[m*4+8:m*4+12][2]+j1[m*4+8:m*4+12][3])
            e15.add(8*j1[m*4+12:m*4+16][0]+4*j1[m*4+12:m*4+16][1]+2*j1[m*4+12:m*4+16][2]+j1[m*4+12:m*4+16][3])             

                       # Checking if the pattern matches or not
        if [len(e0),len(e1),len(e2),len(e3)]==Pattern_S8[faulty_column][0]:
            print("1",hex(k))
            K1_0.append(k)
        if [len(e4),len(e5),len(e6),len(e7)]==Pattern_S8[faulty_column][1]:
            print("2",hex(k))
            K1_1.append(k)
        if [len(e8),len(e9),len(e10),len(e11)]==Pattern_S8[faulty_column][2]:
            print("3",hex(k))
            K1_2.append(k)
        if [len(e12),len(e13),len(e14),len(e15)]==Pattern_S8[faulty_column][3]:
            print("4",hex(k))
            K1_3.append(k)
    KEY_K1=2**48 * K1_0[0] + 2**32 * K1_1[0] + 2**16 * K1_2[0]+K1_3[0]
    return KEY_K1
        
        
    


# In[ ]:


# ---------------------------------------- MAIN FUNCTION -------------------------------------------------

c=[]                  # variable to store the list of faulty ciphertexts
KEY_K0prime_xor_k1=0  # variable to store the value of K0' xor K1
KEY_K1=0              # variable to store the value of K1
KEY_K0prime=0         # variable to store the value of K0' 
faulty_nibble=0       # variable to store the position of fault

c = Generate_faulty_ciphertexts()               # Calling the function to generate ciphertexts
 
K0,K1,K2,K3=Check_Balanced_Property_State_13(c) # Calling the function to get the values of K0,K1,K2,K3 i.e. reduced possible columnwise key guesses of K0' xor K1 

faulty_nibble,K0prime_xor_k1 = Check_Pattern_State_13(K0,K1,K2,K3,c)  # Calling the function to get the exact fault position and value of K0' xor K1

print("FAULTY nibble was ",faulty_nibble)  # Displaying  fault position
print("K0' xor K1 = ",K0prime_xor_k1)      # Displaying  K0' xor K1

KEY_K1=Check_Pattern_State_8(faulty_nibble,K0prime_xor_k1) # Calling the function to return us the value of K1 based on pattren of state 8



for i in range(0,64):  #converting bitarray to integer form
    KEY_K0prime_xor_k1+=K0prime_xor_k1[63-i]* 2**i

KEY_K0prime = KEY_K1 ^ KEY_K0prime_xor_k1 # Getting the value of K0'


print("K1 = ",KEY_K1)       # Displaying  K1
print("K0' = ",KEY_K0prime) # Displaying  K0'




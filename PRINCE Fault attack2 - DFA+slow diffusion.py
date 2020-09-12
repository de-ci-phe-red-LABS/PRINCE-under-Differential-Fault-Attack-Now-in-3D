#!/usr/bin/env python
# coding: utf-8

# In[1]:


# Prince implementation


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


#------------------------------- function to Generate faulty ciphertexts --------------------------------------
def Generate_faulty_ciphertexts():
    
    p=BitArray("0x0275371212374444")
    key=BitArray("0x12341234567c0000ab01234abcdefaab")
    final="0x0000000000000000"
    c=[]
    
    for i in (0,1,2,4,8):                                # for Fault values - 1,2,4,8
            A =  BitArray("0x"+"%01x"%i+"%015x"%0)
            k0 = key[0:64]
            k0prime = k0.copy()
            k0prime.ror(1)
            k0prime ^= k0 >> 63
            k1 = key[64:128]
            data = k0 ^ p                                 # pre-whitening
            data ^= k1 ^ RC[0]

            data = sbox(mprime(sbox(firstrounds(data, k1),S)),Sinv)
            for idx in (6,7,8,9,10):
                data ^= k1 ^ RC[idx]
                if idx==8:
                    data = data ^ A                       # Fault induction
                data = sbox(mprime(shiftrows(data, inverse = True)),Sinv)
            data =  data ^ k1 ^ RC[11]
            data= (data ^ k0prime) 
            c.append(data)
            
    print("K0 ",k0) 
    print("K1 ",k1) 
    print("K0prime ",k0prime) 
    print("K1^K0prime ",k1^k0prime) 
    return c


# In[3]:


#---------- Function to reduce key space of k0' xor k1 by matching with state 4 for 1st ciphertext ------------

def match_state_5_1(r,q):
    K0=[]
    K1=[]
    K2=[]
    K3=[]
    for i in range(2**16):
        m=BitArray("0x"+"%04x"%i+"%04x"%i+"%04x"%i+"%04x"%i)
        p1= r^m^RC[11]
        p2= q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[4:8]==BitArray("0x0"):   # Checking for inactivity
            K0.append(i)
        if p[24:28]==BitArray("0x0"):
            K1.append(i) 
        if p[44:48]==BitArray("0x0"):
            K2.append(i)
        if p[48:52]==BitArray("0x0"):
            K3.append(i)
    return K0,K1,K2,K3
        


# In[4]:


#----- Function to further reduce the key space of k0' xor k1 by matching with state 4 for 2nd ciphertext -----

def match_state_5_2(K0,K1,K2,K3,r,q):
    k00=[]
    k11=[]
    k22=[]
    k33=[]
    for i in K0:
        m=BitArray("0x"+"%04x"%i+"%012x"%0)  # Checking for inactivity in column 1
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[8:12]==BitArray("0x0") :
            k00.append(i)
    for i in K1:
        m=BitArray("0x"+"%08x"%i+"%08x"%0)  # Checking for inactivity in column 2
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[28:32]==BitArray("0x0") :
            k11.append(i) 
    for i in K2:
        m=BitArray("0x"+"%012x"%i+"%04x"%0)  # Checking for inactivity in column 3
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[32:36]==BitArray("0x0"):
            k22.append(i)
    for i in K3:
        m=BitArray("0x"+"%016x"%i)           # Checking for inactivity in column 4
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[52:56]==BitArray("0x0"):
            k33.append(i)
    return k00,k11,k22,k33
    


# In[5]:


#----- Function to further reduce the key space of k0' xor k1 by matching with state 4 for 3rd ciphertext -----

def match_state_5_3(k00,k11,k22,k33,r,q):
    k000=[]
    k111=[]
    k222=[]
    k333=[]
    for i in k00:
        m=BitArray("0x"+"%04x"%i+"%012x"%0)  # Checking for inactivity in column 1
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[12:16]==BitArray("0x0") :
            k000.append(i)
    for i in k11:
        m=BitArray("0x"+"%08x"%i+"%08x"%0)  # Checking for inactivity in column 2
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[16:20]==BitArray("0x0") :
            k111.append(i) 
    for i in k22:
        m=BitArray("0x"+"%012x"%i+"%04x"%0)  # Checking for inactivity in column 3
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[36:40]==BitArray("0x0"):
            k222.append(i)
    for i in k33:
        m=BitArray("0x"+"%016x"%i)          # Checking for inactivity in column 4
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[56:60]==BitArray("0x0"):
            k333.append(i)
    return k000,k111,k222,k333


# In[6]:


#----- Function to further reduce the key space of k0' xor k1 by matching with state 4 for 4th ciphertext -----


def match_state_5_4(k000,k111,k222,k333,r,q):
    k0000=[]
    k1111=[]
    k2222=[]
    k3333=[]
    for i in k000:
        m=BitArray("0x"+"%04x"%i+"%012x"%0)  # Checking for inactivity in column 1
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[0:4]==BitArray("0x0") :
            k0000.append(i)
    for i in k111:
        m=BitArray("0x"+"%08x"%i+"%08x"%0)  # Checking for inactivity in column 2
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[20:24]==BitArray("0x0") :
            k1111.append(i) 
    for i in k222:
        m=BitArray("0x"+"%012x"%i+"%04x"%0)  # Checking for inactivity in column 3 
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[40:44]==BitArray("0x0"):
            k2222.append(i)
    for i in k333:
        m=BitArray("0x"+"%016x"%i)           # Checking for inactivity in column 4
        p1=r^m^RC[11]
        p2=q^m^RC[11]
        p1=sbox(p1,S)
        p2=sbox(p2,S)
        p1=mprime(p1)
        p2=mprime(p2)
        p=p1 ^ p2
        if p[60:64]==BitArray("0x0"):
            k3333.append(i)
    return k0000,k1111,k2222,k3333

    


# In[7]:


# ---------------------- Function to merge the 4 column key spaces of k0' xor k1 ------------------------------

def merge(k0000,k1111,k2222,k3333):
    k0123=[]
    for i in k0000:
        for j in k1111:
            for k in k2222:
                for l in k3333:
                    m=BitArray("0x"+"%04x"%i+"%04x"%j+"%04x"%k+"%04x"%l)
                    k0123.append(m)
    return k0123


# In[8]:


# --------- Function to reduce key spaces of k0' xor k1 and also guess column wise key space of k1 ------------


def match_state_3_1(k0123,r,q):
    k0f=[]
    k1f=[]
    k2f=[]
    k3f=[]
    k0123f=[]
    for i in k0123:
        p1=shiftrows(mprime(sbox(r^i^RC[11],S)),inverse=False)
        p2=shiftrows(mprime(sbox(q^i^RC[11],S)),inverse=False)
        flag0=0
        flag1=0
        flag2=0
        flag3=0
        key0=[]
        key1=[]
        key2=[]
        key3=[]
        for j in range(2**16):     
            m=BitArray("0x"+"%04x"%j+"%04x"%j+"%04x"%j+"%04x"%j)
            p3=mprime(sbox(p1^i^RC[10]^m,S))
            p4=mprime(sbox(p2^i^RC[10]^m,S))
            p=p3^p4
            if p[0:4]!=BitArray("0x0") and (p[4:16] == BitArray("0x000")) :
                key0.append(j)
                flag0=1
            if p[16:20]==BitArray("0x0") and p[20:24]!=BitArray("0x0") and (p[24:32] == BitArray("0x00")) :
                key1.append(j)
                flag1=1
            if p[32:40]==BitArray("0x00") and p[40:44]!=BitArray("0x0") and (p[44:48] == BitArray("0x0")) :
                key2.append(j)
                flag2=1
            if p[48:64]==BitArray("0x0000")  :
                key3.append(j)
                flag3=1
                
        #Remove the key from k0' xor k1  if no satisfying k1 was found
        if flag0==1 and flag1==1 and flag2==1 and flag3==1: 
            k0123f.append(i)
            k0f.append(key0)
            k1f.append(key1)
            k2f.append(key2)
            k3f.append(key3)
            
    return k0123f,k0f,k1f,k2f,k3f
            


# In[9]:


# -------- Function to reduce key spaces of k0' xor k1 and further reduce column wise key space of k1 ---------

def match_state_3_2(k0123f,r,q):
    k00f=[]
    k11f=[]
    k22f=[]
    k33f=[]
    k0123ff=[]
    for i in k0123f:    
        p1=shiftrows(mprime(sbox(r^i^RC[11],S)),inverse=False)
        p2=shiftrows(mprime(sbox(q^i^RC[11],S)),inverse=False)
        flag0=0
        flag1=0
        flag2=0
        flag3=0
        key0=[]
        key1=[]
        key2=[]
        key3=[]
        for j in range(2**16):     
            m=BitArray("0x"+"%04x"%j+"%04x"%j+"%04x"%j+"%04x"%j)
            p3=mprime(sbox(p1^i^RC[10]^m,S))
            p4=mprime(sbox(p2^i^RC[10]^m,S))
            p=p3^p4
            if p[0:4]!=BitArray("0x0") and (p[4:16] == BitArray("0x000")) :
                key0.append(j)
                flag0=1
            if p[16:20]==BitArray("0x0") and p[20:24]!=BitArray("0x0") and (p[24:32] == BitArray("0x00")) :
                key1.append(j)
                flag1=1
            if p[48:60]==BitArray("0x000") and p[60:64]!=BitArray("0x0") :
                key3.append(j)
                flag2=1
            if p[32:48]==BitArray("0x0000")  :
                key2.append(j)
                flag3=1
                
        #Remove the key from k0' xor k1  if no satisfying k1 was found
        if flag0==1 and flag1==1 and flag2==1 and flag3==1:
            k0123ff.append(i)
            k00f.append(key0)
            k11f.append(key1)
            k22f.append(key2)
            k33f.append(key3)
    return k0123ff,k00f,k11f,k22f,k33f
            


# In[10]:


#----- Function to further take the intersecton of the two column key spaces and thereby reduce k0' xor k1 -----
def merge_1(k0123ff,k0f,k00f,k1f,k11f,k2f,k22f,k3f,k33f):
    k0ff=[]
    k1ff=[]
    k2ff=[]
    k3ff=[]
    for i in range(len(k0123ff)):
        k=[]
        # k0
        for j in k0f[i]:
            if j in k00f[i]:
                k.append(j)
        k0ff.append(k)
        k=[]

        for j in k1f[i]:
            if j in k11f[i]:
                k.append(j)
        k1ff.append(k)
        k=[]

        for j in k2f[i]:
            if j in k22f[i]:
                k.append(j)
        k2ff.append(k)
        k=[]

        for j in k3f[i]:
            if j in k33f[i]:
                k.append(j)
        k3ff.append(k)
        
    keyd=[]
    k0fff=[]
    k1fff=[]
    k2fff=[]
    k3fff=[]
    
    # Remove the key from k0' xor k1  if either of the corresponding column spaces of k1 are zero 
    for i in range(len(k0123ff)):
        if len(k0ff[i])!=0 and len(k1ff[i])!=0 and len(k2ff[i])!=0 and len(k3ff[i])!=0:
            keyd.append(k0123ff[i])
            k0fff.append(k0ff[i])
            k1fff.append(k1ff[i])
            k2fff.append(k2ff[i])
            k3fff.append(k3ff[i])
            
    return keyd,k0fff,k1fff,k2fff,k3fff


# In[11]:


# -------- Function to reduce key spaces of k0' xor k1 and further reduce column wise key space of k1 ---------

def match_state_3_3(keyd,r,q):
    k00f=[]
    k11f=[]
    k22f=[]
    k33f=[]
    k0123ff=[]
    for i in keyd:    
        p1=shiftrows(mprime(sbox(r^i^RC[11],S)),inverse=False)
        p2=shiftrows(mprime(sbox(q^i^RC[11],S)),inverse=False)
        flag0=0
        flag1=0
        flag2=0
        flag3=0
        key0=[]
        key1=[]
        key2=[]
        key3=[]
        for j in range(2**16):     
            m=BitArray("0x"+"%04x"%j+"%04x"%j+"%04x"%j+"%04x"%j)
            p3=mprime(sbox(p1^i^RC[10]^m,S))
            p4=mprime(sbox(p2^i^RC[10]^m,S))
            p=p3^p4
            if p[0:4]!=BitArray("0x0") and (p[4:16] == BitArray("0x000")) :
                key0.append(j)
                flag0=1
            if p[32:40]==BitArray("0x00") and p[40:44]!=BitArray("0x0") and (p[44:48] == BitArray("0x0")) :
                key2.append(j)
                flag1=1
            if p[48:60]==BitArray("0x000") and p[60:64]!=BitArray("0x0") :
                key3.append(j)
                flag2=1
            if p[16:32]==BitArray("0x0000")  :
                key1.append(j)
                flag3=1
                
        #Remove the key from k0' xor k1  if no satisfying k1 was found
        if flag0==1 and flag1==1 and flag2==1 and flag3==1:
            k0123ff.append(i)
            k00f.append(key0)
            k11f.append(key1)
            k22f.append(key2)
            k33f.append(key3)
    return k0123ff,k00f,k11f,k22f,k33f


# In[12]:


# -------- Function to reduce key spaces of k0' xor k1 and further reduce column wise key space of k1 ---------

def match_state_3_4(keyd,r,q):
    k00f=[]
    k11f=[]
    k22f=[]
    k33f=[]
    k0123ff=[]
    for i in keyd:    
        p1=shiftrows(mprime(sbox(r^i^RC[11],S)),inverse=False)
        p2=shiftrows(mprime(sbox(q^i^RC[11],S)),inverse=False)
        flag0=0
        flag1=0
        flag2=0
        flag3=0
        key0=[]
        key1=[]
        key2=[]
        key3=[]
        for j in range(2**16):     
            m=BitArray("0x"+"%04x"%j+"%04x"%j+"%04x"%j+"%04x"%j)
            p3=mprime(sbox(p1^i^RC[10]^m,S))
            p4=mprime(sbox(p2^i^RC[10]^m,S))
            p=p3^p4
            if p[16:20]==BitArray("0x0") and p[20:24]!=BitArray("0x0") and (p[24:32] == BitArray("0x00")) :
                key1.append(j)
                flag0=1
            if p[32:40]==BitArray("0x00") and p[40:44]!=BitArray("0x0") and (p[44:48] == BitArray("0x0")) :
                key2.append(j)
                flag1=1
            if p[48:60]==BitArray("0x000") and p[60:64]!=BitArray("0x0") :
                key3.append(j)
                flag2=1
            if p[0:16]==BitArray("0x0000")  :
                key0.append(j)
                flag3=1
         #Remove the key from k0' xor k1  if no satisfying k1 was found
        if flag0==1 and flag1==1 and flag2==1 and flag3==1:
            k0123ff.append(i)
            k00f.append(key0)
            k11f.append(key1)
            k22f.append(key2)
            k33f.append(key3)
    return k0123ff,k00f,k11f,k22f,k33f
            


# In[ ]:


# ---------------------------------------- MAIN function ------------------------------------------------------

c=[]    #Variable to store original ciphertext and faulty ciphertexts    
c = Generate_faulty_ciphertexts() # Function to generate and return original and faulty ciphertexts

#for fault in range(0,16):

fault=0
print("--------------------------------")
print(" ---------  fault at ---------- ",fault)
print("--------------------------------")


"""
c_1=[]

if fault in [0,3,4,5]:
    c_1.append(c[1])
    c_1.append(c[2])
    c_1.append(c[3])
    c_1.append(c[4])
elif fault in [1,2,13,15]:
    c_1.append(c[4])
    c_1.append(c[1])
    c_1.append(c[2])
    c_1.append(c[3])
elif fault in [6,7,8,11]:
    c_1.append(c[2])
    c_1.append(c[3])
    c_1.append(c[4])
    c_1.append(c[1])
else:
    c_1.append(c[3])
    c_1.append(c[4])
    c_1.append(c[1])
    c_1.append(c[2])"""

k0,k1,k2,k3 = match_state_5_1(c[0],c[1])  # Function to refine the key guess for k0' xor k1
k0,k1,k2,k3 = match_state_5_2(k0,k1,k2,k3,c[0],c[2]) # Function to further refine the key guess for k0' xor k1
k0,k1,k2,k3 = match_state_5_3(k0,k1,k2,k3,c[0],c[3]) # Function to further refine the key guess for k0' xor k1
k0,k1,k2,k3 = match_state_5_4(k0,k1,k2,k3,c[0],c[4]) # Function to further refine the key guess for k0' xor k1

k0123 = merge(k0,k1,k2,k3)                   # Funciton to merge the 4 sets of  key guesses of each column

k0123,k0_1,k1_1,k2_1,k3_1 = match_state_3_1(k0123,c[0],c[1]) #Function to refine the key guess for k0' xor k1 and k1
k0123,k0_2,k1_2,k2_2,k3_2 = match_state_3_2(k0123,c[0],c[2]) #Function to further refine the key guess for k0' xor k1 and k1
k0123,k0,k1,k2,k3 = merge_1(k0123,k0_1,k0_2,k1_1,k1_2,k2_1,k2_2,k3_1,k3_2) #Function to take intersection of the two sets of column spaces and redice k0' xor k1  
k0123,k0_2,k1_2,k2_2,k3_2 = match_state_3_3(k0123,c[0],c[3]) #Function to further refine the key guess for k0' xor k1 and k1
k0123,k0,k1,k2,k3 = merge_1(k0123,k0,k0_2,k1,k1_2,k2,k2_2,k3,k3_2)
k0123,k0_2,k1_2,k2_2,k3_2 = match_state_3_4(k0123,c[0],c[4]) #Function to further refine the key guess for k0' xor k1 and k1
k0123,k0,k1,k2,k3 = merge_1(k0123,k0,k0_2,k1,k1_2,k2,k2_2,k3,k3_2)

print(k0123) # printing the final value of k0' xor k1
print(hex(k0[0][0]),hex(k1[0][0]),hex(k2[0][0]),hex(k3[0][0])) # printing the column wise keyspace of k1
    
    
    
    
    
    


# In[ ]:





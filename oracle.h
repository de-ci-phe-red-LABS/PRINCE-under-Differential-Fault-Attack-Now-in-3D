#include<stdio.h>
#include <time.h>

long rand_64_bit(void){
    int a,b;
    long c = 0;
    a = rand()&0xffffffff;
    b = rand()&0xffffffff;
    c = ((long)a<<32)|b;
    return c;
}

long circ_shift(long x,int pos){	
    /* right circular shifting the msg to 'pos' position */
	return ((x>>pos)|(x<<(64-pos)));
}

int sb_table[16] = {0xb,0xf,0x3,0x2,0xa,0xc,0x9,0x1,0x6,0x7,0x8,0x0,0xe,0x5,0xd,0x4};	/* subbyte table */
long SB(long msg){					
    /* takes the msg, extract nibble & substitute by subbyte table and return 64 bit 								   modified msg */
	long return_msg = 0;
	for(int i=0;i<16;i++){
		return_msg = return_msg<<4;
		return_msg = return_msg | sb_table[(msg >> (64 - (4*i + 4)))&0xf];
	}
	return return_msg;
}	

int inv_sb_table[16] = {0xb,0x7,0x3,0x2,0xf,0xd,0x8,0x9,0xa,0x6,0x4,0x0,0x5,0xe,0xc,0x1};	/* the inverse subbyte table */
long inv_SB(long msg){	
    /* takes the msg, extract nibble & substitute by inverse subbyte table and return 								   64 bit modified msg */
	long return_msg = 0;
	for(int i=0;i<16;i++){
		return_msg = return_msg<<4;
		return_msg = return_msg | inv_sb_table[(msg >> (64 - (4*i + 4)))&0xf];
	}
	return return_msg;
}	

long MC(long msg){					
    /* storing the 64x64 matrix like each column is a 64 bit long int, store it in a 								   array M */
	char msg_bit;	long msg_,return_msg = 0;
	long M[64] = 
	{
        	0x0888000000000000, 0x4044000000000000, 0x2202000000000000, 0x1110000000000000,
			0x8880000000000000, 0x0444000000000000, 0x2022000000000000, 0x1101000000000000,
			0x8808000000000000, 0x4440000000000000, 0x0222000000000000, 0x1011000000000000,
			0x8088000000000000, 0x4404000000000000, 0x2220000000000000, 0x0111000000000000,

			0x0000888000000000, 0x0000044400000000, 0x0000202200000000, 0x0000110100000000,
			0x0000880800000000, 0x0000444000000000, 0x0000022200000000, 0x0000101100000000,
			0x0000808800000000, 0x0000440400000000, 0x0000222000000000, 0x0000011100000000, 
			0x0000088800000000, 0x0000404400000000, 0x0000220200000000, 0x0000111000000000,
			
			0x0000000088800000, 0x0000000004440000, 0x0000000020220000, 0x0000000011010000,
			0x0000000088080000, 0x0000000044400000, 0x0000000002220000, 0x0000000010110000,
			0x0000000080880000, 0x0000000044040000, 0x0000000022200000, 0x0000000001110000,
			0x0000000008880000, 0x0000000040440000, 0x0000000022020000, 0x0000000011100000,
			
			0x0000000000000888, 0x0000000000004044, 0x0000000000002202, 0x0000000000001110,
			0x0000000000008880, 0x0000000000000444, 0x0000000000002022, 0x0000000000001101,
			0x0000000000008808, 0x0000000000004440, 0x0000000000000222, 0x0000000000001011,
			0x0000000000008088, 0x0000000000004404, 0x0000000000002220, 0x0000000000000111
	};
	for(int i=0;i<64;i++){
		msg_ = msg&M[i];	
		msg_bit = 0;	
		for(int j=0;j<64;j++)
			msg_bit = ((msg_>>j)&1)^msg_bit;	/* extracting msg bits & checking whether xor is 0 after AND */
		return_msg = (return_msg<<1)|msg_bit;
	}
	return return_msg;
}
				
long SR(long msg){					
    /* storing shift row rule in an array, extracting nibble & checking where the msg 								   goes by the rule */
	char SR_table[16] = {0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11};
	long return_msg = 0;
	
	for(int i=0;i<16;i++)
		return_msg = (return_msg<<4)|(msg>> (60 - (4*SR_table[i]))&0xf);
	return return_msg;
}
		
long inv_SR(long msg){
    /* storing inverse shift row rule in an array, extracting nibble & checking where 								   the msg goes by the rule */
	char inv_SR_table[16] = {0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3};
	long return_msg = 0;
	
	for(int i=0;i<16;i++)
		return_msg = (return_msg<<4)|(msg>> (60 - (4*inv_SR_table[i]))&0xf);
	return return_msg;
}

long oracle(long msg, int version, long k0, long k1){
    /* takes 64 bit msg, returns 64 bit cipher text */
	long PRINCE_V2_rc[12] = {0x0000000000000000,0x13198a2e03707344,0xa4093822299f31d0,0x082efa98ec4e6c89,0x452821e638d01377,0xbe5466cf34e90c6c,0x7ef84f78fd955cb1,0x7aacf4538d971a60,0xc882d32f25323c54,0x9b8ded979cd838c7,0xd3b5a399ca0c2399,0x3f84d5b5b5470917};
	long PRINCE_rc[12] = {0x0000000000000000,0x13198a2e03707344,0xa4093822299f31d0,0x082efa98ec4e6c89,0x452821e638d01377,0xbe5466cf34e90c6c,0x7ef84f78fd955cb1,0x85840851f1ac43aa,0xc882d32f25323c54,0x64a51195e0e3610d,0xd3b5a399ca0c2399,0xc0ac29b7c97c50dd};
	
	long whitening_K;
	if (version==1){
    	long k0Prime = k0 ^ k1;
    	long a = k0Prime << 1;
    	long b = k0Prime >> 63;
    	long c = a ^ b;
    	long d = (c >> 63) << 1;
    	whitening_K = c ^ d;
    	msg ^= whitening_K;
	}
	for(int i=0;i<11;i++){
    	if (version==1){
        	msg = msg^k0^PRINCE_rc[i];
        	msg = (i<5) ? SR(MC(SB(msg))) : (i == 5) ? inv_SB(MC(SB(msg))) : inv_SB(MC(inv_SR(msg)));
    	}        	
    	else{
        	msg = (i%2 == 0) ? msg^k0^PRINCE_V2_rc[i] : msg^k1^PRINCE_V2_rc[i];
    		msg = (i<5) ? SR(MC(SB(msg))) : (i == 5) ? inv_SB(PRINCE_V2_rc[11]^k1^MC(k0^SB(msg))) : inv_SB(MC(inv_SR(msg)));
    	}
	}
	if (version==1)
    	msg = msg^k1^PRINCE_rc[11];
    else
        msg = msg^k1^PRINCE_V2_rc[11];

	return msg;
}
	

	
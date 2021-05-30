#include<stdio.h>

long make_fault_msg(long msg, int bit_number){  
    /* making fault msg by replacing the 'nibble_number' nibble by                                                                             xor-ing it with fault_diff */
    long fault_msg = 0;
    for(int i=0;i<64;i++)
    {
        if(i == bit_number)
        {
            fault_msg = (fault_msg<<1)|(((~msg)>>(63-i))&1);
            continue;
        }
        fault_msg = (fault_msg<<1)|((msg>>(63-i))&1);
    }
    return fault_msg;    
}    


long fault_oracle(long msg, int round, int bit_number, int version, long k0, long k1){ 
    /* introduces fault at 'round'-th round by xor-ing the                                                                                     'nibble_number' nibble with 'fault_difff' */
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
    	if(i == round)                                          /* doing fault in 'round'-th round */
            msg = make_fault_msg(msg,bit_number);
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

long fault_oracle_dec(long msg, int round, int bit_number, int version, long k0, long k1){
    long PRINCE_V2_rc[12] = {0x0000000000000000,0x13198a2e03707344,0xa4093822299f31d0,0x082efa98ec4e6c89,0x452821e638d01377,0xbe5466cf34e90c6c,0x7ef84f78fd955cb1,0x7aacf4538d971a60,0xc882d32f25323c54,0x9b8ded979cd838c7,0xd3b5a399ca0c2399,0x3f84d5b5b5470917};
	long PRINCE_rc[12] = {0x0000000000000000,0x13198a2e03707344,0xa4093822299f31d0,0x082efa98ec4e6c89,0x452821e638d01377,0xbe5466cf34e90c6c,0x7ef84f78fd955cb1,0x85840851f1ac43aa,0xc882d32f25323c54,0x64a51195e0e3610d,0xd3b5a399ca0c2399,0xc0ac29b7c97c50dd};
	long alpha = PRINCE_rc[11], beta = PRINCE_V2_rc[11];
	long whitening_K, k1_dec_v1, k0_dec_v2, k1_dec_v2, new_k0_dec_v2, new_k1_dec_v2;
	if (version==1){
    	long k0Prime = k0 ^ k1;
    	long a = k0Prime << 1;
    	long b = k0Prime >> 63;
    	long c = a ^ b;
    	long d = (c >> 63) << 1;
    	whitening_K = c ^ d;
    	msg ^= k0Prime;
    	k1_dec_v1 = k0 ^ alpha;
	}
	else{
    	k0_dec_v2 = k1 ^ beta;
    	k1_dec_v2 = k0 ^ alpha;
    	new_k0_dec_v2 = k0_dec_v2 ^ alpha ^ beta;
    	new_k1_dec_v2 = k1_dec_v2 ^ alpha ^ beta;
	}
	
	for(int i=0;i<11;i++){
    	if (version==1){
        	msg = msg^k1_dec_v1^PRINCE_rc[i];
        	msg = (i<5) ? SR(MC(SB(msg))) : (i == 5) ? inv_SB(MC(SB(msg))) : inv_SB(MC(inv_SR(msg)));
    	}        	
    	else{
        	if (i<=5)
            	msg = (i%2 == 0) ? msg^k0_dec_v2^PRINCE_V2_rc[i] : msg^k1_dec_v2^PRINCE_V2_rc[i];
            else
                msg = (i%2 == 0) ? msg^new_k0_dec_v2^PRINCE_V2_rc[i] : msg^new_k1_dec_v2^PRINCE_V2_rc[i];
    		msg = (i<5) ? SR(MC(SB(msg))) : (i == 5) ? inv_SB(PRINCE_V2_rc[11]^new_k1_dec_v2^MC(k0_dec_v2^SB(msg))) : inv_SB(MC(inv_SR(msg)));
    	}
    	if(i == round)                                          /* doing fault in 'round'-th round */
            msg = make_fault_msg(msg,bit_number);
	}
	if (version==1)
    	msg = msg^k1_dec_v1^whitening_K^PRINCE_rc[11];
    else
        msg = msg^new_k1_dec_v2^PRINCE_V2_rc[11];

	return msg;
}
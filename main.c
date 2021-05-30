#include <stdio.h>
#include <stdlib.h>
#include "oracle.h"
#include "fault_oracle.h"

#define limit (1<<16)                                                           // total key values for 1 sheet
#define round 8

void dec_1_round(int version, int sheet, int guess_key_value, long cip, long fault_cip, long *dec_cip, long *dec_fault_cip){
    // decrypting 1-round & stores dec values in dec_cip, dec_fault_cip
    long rc_11;
    if (version==1)
        rc_11 = 0xc0ac29b7c97c50dd;
    else
        rc_11 = 0x3f84d5b5b5470917;
    *dec_cip = MC(SB(cip^rc_11^((long)guess_key_value<<(48 - 16*sheet))));
    *dec_fault_cip = MC(SB(fault_cip^rc_11^((long)guess_key_value<<(48 - 16*sheet))));
}

void dec_2_round(int version, int sheet, int guess_key_value, long guess_k1, long cip, long fault_cip, long *dec_cip, long *dec_fault_cip){
    // decrypting 2-round & stores dec values in dec_cip, dec_fault_cip
    long rc_10 = 0xd3b5a399ca0c2399, rc_11;
    if (version==1)
        rc_11 = 0xc0ac29b7c97c50dd;
    else
        rc_11 = 0x3f84d5b5b5470917;

    cip = SR(MC(SB(cip^rc_11^guess_k1)));
    fault_cip = SR(MC(SB(fault_cip^rc_11^guess_k1)));

    *dec_cip = MC(SB(cip^rc_10^((long)guess_key_value<<(48 - 16*sheet))));
    *dec_fault_cip = MC(SB(fault_cip^rc_10^((long)guess_key_value<<(48 - 16*sheet))));
}

void dec_3_round(int version, long guess_k1, long guess_k0, long cip, long fault_cip, long *dec_cip, long *dec_fault_cip){
	// decrypting 3-round & stores dec values in dec_cip, dec_fault_cip
	long rc_9, rc_10 = 0xd3b5a399ca0c2399, rc_11;
    if (version==1){
        rc_9 = 0x64a51195e0e3610d;
        rc_11 = 0xc0ac29b7c97c50dd;
    }
    else{
        rc_9 = 0x9b8ded979cd838c7;
        rc_11 = 0x3f84d5b5b5470917;
    }
	
	cip = SR(MC(SB(cip^rc_11^guess_k1)));
	fault_cip = SR(MC(SB(fault_cip^rc_11^guess_k1)));

	cip = SR(MC(SB(cip^rc_10^guess_k0)));
	fault_cip = SR(MC(SB(fault_cip^rc_10^guess_k0)));
	
	if (version==1){
    	*dec_cip = MC(SB(cip^rc_9^guess_k0));
    	*dec_fault_cip = MC(SB(fault_cip^rc_9^guess_k0));
	}
	else{
    	*dec_cip = MC(SB(cip^rc_9^guess_k1));
    	*dec_fault_cip = MC(SB(fault_cip^rc_9^guess_k1));
	}
}

int check_pattern_state_8(int version, int sheet, int guess_key_value, long cip, long fault_cip){
    long dec_cip = 0, dec_fault_cip = 0, diff;
    // dec 1-round and store value in dec_cip & dec_fault_cip
    dec_1_round(version, sheet, guess_key_value, cip, fault_cip, &dec_cip, &dec_fault_cip);
    diff = dec_cip ^ dec_fault_cip;
    if((sheet == 0) && ((((diff>>60)&0xf) == 0) || (((diff>>56)&0xf) == 0) || (((diff>>52)&0xf) == 0) || (((diff>>48)&0xf) == 0)))
        return 1;
    if((sheet == 1) && ((((diff>>44)&0xf) == 0) || (((diff>>40)&0xf) == 0) || (((diff>>36)&0xf) == 0) || (((diff>>32)&0xf) == 0)))
        return 1;
    if((sheet == 2) && ((((diff>>28)&0xf) == 0) || (((diff>>24)&0xf) == 0) || (((diff>>20)&0xf) == 0) || (((diff>>16)&0xf) == 0)))
        return 1;
    if((sheet == 3) && ((((diff>>12)&0xf) == 0) || (((diff>>8)&0xf) == 0) || (((diff>>4)&0xf) == 0) || (((diff>>0)&0xf) == 0)))
        return 1;
    return 0;
}

int check_pattern_state_5(int version, int sheet, int guess_key_value, long guess_k1, long cip, long fault_cip){	
    long dec_cip = 0, dec_fault_cip = 0, diff;
    dec_2_round(version, sheet, guess_key_value, guess_k1, cip, fault_cip, &dec_cip, &dec_fault_cip);
	diff = dec_cip^dec_fault_cip;
	
	if((sheet == 0) && (((((diff>>60)&0xf) == 0) && (((diff>>56)&0xf) == 0) && (((diff>>52)&0xf) == 0) && (((diff>>48)&0xf) == 0))
			|| ((((diff>>56)&0xf) == 0) && (((diff>>52)&0xf) == 0) && (((diff>>48)&0xf) == 0))
			|| ((((diff>>60)&0xf) == 0) && (((diff>>52)&0xf) == 0) && (((diff>>48)&0xf) == 0))
			|| ((((diff>>60)&0xf) == 0) && (((diff>>56)&0xf) == 0) && (((diff>>48)&0xf) == 0))
			|| ((((diff>>60)&0xf) == 0) && (((diff>>56)&0xf) == 0) && (((diff>>52)&0xf) == 0))))
		return 1;
	
	if((sheet == 1) && (((((diff>>44)&0xf) == 0) && (((diff>>40)&0xf) == 0) && (((diff>>36)&0xf) == 0) && (((diff>>32)&0xf) == 0))
			|| ((((diff>>40)&0xf) == 0) && (((diff>>36)&0xf) == 0) && (((diff>>32)&0xf) == 0))
			|| ((((diff>>44)&0xf) == 0) && (((diff>>36)&0xf) == 0) && (((diff>>32)&0xf) == 0))
			|| ((((diff>>44)&0xf) == 0) && (((diff>>40)&0xf) == 0) && (((diff>>32)&0xf) == 0))
			|| ((((diff>>44)&0xf) == 0) && (((diff>>40)&0xf) == 0) && (((diff>>36)&0xf) == 0))))
		return 1;

	if((sheet == 2) && (((((diff>>28)&0xf) == 0) && (((diff>>24)&0xf) == 0) && (((diff>>20)&0xf) == 0) && (((diff>>16)&0xf) == 0))
			|| ((((diff>>24)&0xf) == 0) && (((diff>>20)&0xf) == 0) && (((diff>>16)&0xf) == 0))
			|| ((((diff>>28)&0xf) == 0) && (((diff>>20)&0xf) == 0) && (((diff>>16)&0xf) == 0))
			|| ((((diff>>28)&0xf) == 0) && (((diff>>24)&0xf) == 0) && (((diff>>16)&0xf) == 0))
			|| ((((diff>>28)&0xf) == 0) && (((diff>>24)&0xf) == 0) && (((diff>>20)&0xf) == 0))))
		return 1;

	if((sheet == 3) && (((((diff>>12)&0xf) == 0) && (((diff>>8)&0xf) == 0) && (((diff>>4)&0xf) == 0) && (((diff>>0)&0xf) == 0))
			|| ((((diff>>8)&0xf) == 0) && (((diff>>4)&0xf) == 0) && (((diff>>0)&0xf) == 0))
			|| ((((diff>>12)&0xf) == 0) && (((diff>>4)&0xf) == 0) && (((diff>>0)&0xf) == 0))
			|| ((((diff>>12)&0xf) == 0) && (((diff>>8)&0xf) == 0) && (((diff>>0)&0xf) == 0))
			|| ((((diff>>12)&0xf) == 0) && (((diff>>8)&0xf) == 0) && (((diff>>4)&0xf) == 0))))
		return 1;
	
	return 0;
}

int check_pattern_state_2(int version, long guess_k1, long guess_k0, long cip, long fault_cip){
    long dec_cip = 0, dec_fault_cip = 0, diff;
    dec_3_round(version, guess_k1, guess_k0, cip, fault_cip, &dec_cip, &dec_fault_cip);
    diff = dec_cip^dec_fault_cip;
    
    int count = 0;
    for(int bit=0; bit<64; bit++){
		count = count + ((diff>>bit)&1);
		if(count > 1)
			return 0;
	}
	return 1;
}
	
void merge_key_columns(int ctr_k1[4][limit], long **k1_list, int total_k1){
    int ctr = 0;
    for(long column_0 = 0; column_0<limit ; column_0++){
        if(ctr_k1[0][column_0] == 0)
            continue;
        for(long column_1 = 0; column_1<limit ; column_1++){
            if(ctr_k1[1][column_1] == 0)
                continue;
            for(long column_2 = 0; column_2<limit ; column_2++){
                if(ctr_k1[2][column_2] == 0)
                    continue;
                for(long column_3 = 0; column_3<limit ; column_3++){
                    if(ctr_k1[3][column_3] == 0)
                        continue;
                    long k1_val = (((column_0&0xffff)<<48)|((column_1&0xffff)<<32)|((column_2&0xffff)<<16)|((column_3&0xffff)<<0));
                    k1_list[ctr++][0] = k1_val;
                }
            }
        }
    }
}

void launch_attack(int number_of_fault, int version, long k0, long k1, int reflection){
    srand(time(0));
    long msg, *cip, *fault_cip, guess_k1 = 0;
    int ctr_k1[4][1<<16], ctr_k0[4][1<<16], bit_number, times_k0 = 0, times_k1 = 0;
    
    for(int sheet=0; sheet<4; sheet++)
        for(int pos=0;pos<limit;pos++){    
            ctr_k1[sheet][pos] = 1;                                    // initialize ctr to 1 for each sheet
            ctr_k0[sheet][pos] = 0;
        }
    
    //--------------------------------------quering oracle and fault_oracle----------------------------------------------------------
    cip = (long*)malloc(number_of_fault*sizeof(long));
    fault_cip = (long*)malloc(number_of_fault*sizeof(long));
    
    for(int count = 0; count < number_of_fault; count++){
        bit_number = rand_64_bit()%64;                          // varring bit number randomly upon number of fault
        msg = rand_64_bit();                                            // taking msg randomly for each fault
        if (reflection){
            fault_cip[count] = msg;
            long plaintext = fault_oracle_dec(msg, 10-round, bit_number, version, k0, k1);
            cip[count] = oracle(plaintext, version, k0, k1);
        }
        else{
            cip[count] = oracle(msg, version, k0, k1);
            fault_cip[count] = fault_oracle(msg, round, bit_number, version, k0, k1);                // giving differential fault
        }
    }
    
    //-----------------------------------------------retrieving k1---------------------------------------------------------------------
    for(int count = 0; count < number_of_fault; count++){
        for(int sheet = 0; sheet<4; sheet++){
            for(int guess_key_value=0; guess_key_value<limit; guess_key_value++){
                if (ctr_k1[sheet][guess_key_value] == 0)
                    continue;
                if (check_pattern_state_8(version, sheet, guess_key_value, cip[count], fault_cip[count]) != 1)
                    ctr_k1[sheet][guess_key_value] = 0;          // decrease ctr if xor is not 0 in that nibble
            }
        }
    }
    
    long **k1_list;    
    long count_k1[4] = {0};
    int total_k1 = 1;
    for (int sheet = 0; sheet<4; sheet++){
        for (int guess_key_value=0; guess_key_value<limit; guess_key_value++)
            if (ctr_k1[sheet][guess_key_value] == 1){
                    count_k1[sheet]++;
            }
        total_k1 *= count_k1[sheet];
    }
    k1_list = (long**)malloc(total_k1 * sizeof(long *));
    for (int i=0; i<total_k1; i++){
        k1_list[i] = (long*)malloc(2 * sizeof(long));
        k1_list[i][1] = 1;
    }
    merge_key_columns(ctr_k1, k1_list, total_k1);
    
    //-----------------------------------------------retrieving k0---------------------------------------------------------------------
    for (int ctr=0; ctr<total_k1; ctr++){
        int sum_flag_k1_fault = 0;
        int suggest_ctr_k0[4][limit] = {0};
        for (int count = 0; count < number_of_fault; count++){
            if (count!=0 && sum_flag_k1_fault!=count)
                break;
            int flag_k1[4] = {0};
            for (int sheet = 0; sheet<4; sheet++){
                for(int guess_key_value=0; guess_key_value<limit; guess_key_value++){
                    if (count!=0 && suggest_ctr_k0[sheet][guess_key_value] == 0)
                        continue;
                    if (check_pattern_state_5(version, sheet, guess_key_value, k1_list[ctr][0], cip[count], fault_cip[count]) == 1){
                        suggest_ctr_k0[sheet][guess_key_value] = 1;
                        flag_k1[sheet] = 1;
                    }
                    else
                        suggest_ctr_k0[sheet][guess_key_value] = 0;
                }
            }
            if (flag_k1[0] && flag_k1[1] && flag_k1[2] && flag_k1[3])
                sum_flag_k1_fault += 1;
        }
        if (sum_flag_k1_fault == number_of_fault){
            for(int sheet = 0; sheet<4; sheet++){
                for(int guess_key_value=0; guess_key_value<limit; guess_key_value++){
                    if (ctr_k0[sheet][guess_key_value] != 1 && suggest_ctr_k0[sheet][guess_key_value] == 1)
                        ctr_k0[sheet][guess_key_value] = 1;
                }
            }
        }
        else{
            k1_list[ctr][1] = 0;
        }
    }
    
    long **k0_list;
    long count_k0[4] = {0};
    int total_k0 = 1;
    for (int sheet = 0; sheet<4; sheet++){
        for (int guess_key_value=0; guess_key_value<limit; guess_key_value++)
            if (ctr_k0[sheet][guess_key_value] == 1){
                    count_k0[sheet]++;
            }
        total_k0 *= count_k0[sheet];
    }
    k0_list = (long**)malloc(total_k0 * sizeof(long *));
    for (int i=0; i<total_k0; i++){
        k0_list[i] = (long*)malloc(2 * sizeof(long));
        k0_list[i][1] = 1;
    }
    merge_key_columns(ctr_k0, k0_list, total_k0);
    
    //-----------------------------------------------reducing k0 and k1 more---------------------------------------------------------------------
    printf("\nAfter Attack: =======================> \n");
    for (int ctr_k1=0; ctr_k1<total_k1; ctr_k1++){
        if (k1_list[ctr_k1][1] == 0)
            continue;
        for (int ctr_k0=0; ctr_k0<total_k0; ctr_k0++){
            if (k0_list[ctr_k0][1] == 0)
                continue;
            int foundKey = 0;
            for (int count = 0; count < number_of_fault; count++){
                if (check_pattern_state_2(version, k1_list[ctr_k1][0], k0_list[ctr_k0][0], cip[count], fault_cip[count]) == 1){
                    foundKey ++;
                }
            }
            if (foundKey == number_of_fault){
                if (version==1){
                    long k0Prime = k0_list[ctr_k0][0] ^ k1_list[ctr_k1][0];
                    printf ("K1: \t 0x%016lx\n", k0_list[ctr_k0][0]);
                    printf ("K0-Prime: \t 0x%016lx\n", k0Prime);
                    printf ("K1 ^ K0-Prime: \t 0x%016lx\n", k1_list[ctr_k1][0]);
                }
                else{
                    printf ("K0: \t 0x%016lx\n", k0_list[ctr_k0][0]);
                    printf ("K1: \t 0x%016lx\n", k1_list[ctr_k1][0]);
                }
                printf ("\n********************\n"); 
            }
        }
    }
    
    free (cip);
    free (fault_cip);
    for (int i=0; i<total_k1; i++){
        free(k1_list[i]);
    }
    free(k1_list);
    for (int i=0; i<total_k0; i++){
        free(k0_list[i]);
    }
    free(k0_list);
}

int main()
{
    printf ("Banashri");
    return 0;
}
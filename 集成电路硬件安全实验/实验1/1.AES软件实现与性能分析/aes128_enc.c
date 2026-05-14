// include the header file
#include "aes.h"

void aes128_enc(unsigned char *key, unsigned char *ptext)
{
    unsigned int round = 0;
    //unsigned char round_key[NUM_ROUND][TXT_LEN]; // initialize to zeros

    key_expansion(key); // key expansion - calculate round keys
    //print_roundkey(round_key); // this is for test
    
    add_key(ptext, key); // first add key
    //print_hex(ptext, "ptext");
    
    // aes one round
    for(round = 0; round <= NUM_ROUND - 2; round++){
        sub_bytes(ptext); // S-Box
        //print_hex(ptext, "sbox");

        shift_rows(ptext); // shift rows
        //print_hex(ptext, "shift_rows");

        mix_columns(ptext); // mix columns
        //print_hex(ptext, "mix_columns");
        
        add_key(ptext, round_key[round + 1]); // add round key
        
		printf("*********round%d********", round);
		print_hex(ptext, "addkey");
    }
    
    // aes final round
    sub_bytes(ptext); // S-Box
    
    shift_rows(ptext); // shift rows
    
    add_key(ptext, round_key[round + 1]); // add round key
    
    print_hex(ptext, "ciphertxt_right");
    
    return;
}

void sub_bytes(unsigned char *ptext)
{
    unsigned int i = 0;
    
    for(i = 0; i < TXT_LEN; i++)
        ptext[i] = sbox(ptext[i]); // S-Box look up
    
    return;
}

void shift_rows(unsigned char *ptext)
{
    unsigned int i = 0;
    unsigned char temp[TXT_LEN] = {0};
    
    // first row
    temp[0] = ptext[0];  temp[4] = ptext[4];  temp[8]  = ptext[8];   temp[12] = ptext[12];
    temp[1] = ptext[5];  temp[5] = ptext[9];  temp[9]  = ptext[13];  temp[13] = ptext[1];
    temp[2] = ptext[10]; temp[6] = ptext[14]; temp[10] = ptext[2];   temp[14] = ptext[6];
    temp[3] = ptext[15]; temp[7] = ptext[3];  temp[11] = ptext[7];   temp[15] = ptext[11];
    
    for(i = 0; i < TXT_LEN; i++)
        ptext[i] = temp[i];
    
    return;
}

// matrix
// [02 03 01 01]
// [01 02 03 01]
// [01 01 02 03]
// [03 01 01 02]
void mix_columns(unsigned char *ptext)
{
    unsigned int i = 0;
    unsigned char temp[TXT_LEN] = {0};
    
    temp[0] =  gf_mult2(ptext[0]) ^ (gf_mult2(ptext[1]) ^ ptext[1]) ^ ptext[2] ^ ptext[3];
    temp[4] =  gf_mult2(ptext[4]) ^ (gf_mult2(ptext[5]) ^ ptext[5]) ^ ptext[6] ^ ptext[7];
    temp[8] =  gf_mult2(ptext[8]) ^ (gf_mult2(ptext[9]) ^ ptext[9]) ^ ptext[10] ^ ptext[11];
    temp[12] = gf_mult2(ptext[12]) ^ (gf_mult2(ptext[13]) ^ ptext[13]) ^ ptext[14] ^ ptext[15];
    
    temp[1] = ptext[0] ^ gf_mult2(ptext[1]) ^ (gf_mult2(ptext[2]) ^ ptext[2]) ^ ptext[3];
    temp[5] = ptext[4] ^ gf_mult2(ptext[5]) ^ (gf_mult2(ptext[6]) ^ ptext[6]) ^ ptext[7];
    temp[9] = ptext[8] ^ gf_mult2(ptext[9]) ^ (gf_mult2(ptext[10]) ^ ptext[10]) ^ ptext[11];
    temp[13] = ptext[12] ^ gf_mult2(ptext[13]) ^ (gf_mult2(ptext[14]) ^ ptext[14]) ^ ptext[15];
    
    temp[2] = ptext[0] ^ ptext[1] ^ gf_mult2(ptext[2]) ^ (gf_mult2(ptext[3]) ^ ptext[3]);
    temp[6] = ptext[4] ^ ptext[5] ^ gf_mult2(ptext[6]) ^ (gf_mult2(ptext[7]) ^ ptext[7]);
    temp[10] = ptext[8] ^ ptext[9] ^ gf_mult2(ptext[10]) ^ (gf_mult2(ptext[11]) ^ ptext[11]);
    temp[14] = ptext[12] ^ ptext[13] ^ gf_mult2(ptext[14]) ^ (gf_mult2(ptext[15]) ^ ptext[15]);
    
    temp[3] = (gf_mult2(ptext[0]) ^ ptext[0]) ^ ptext[1] ^ ptext[2] ^ gf_mult2(ptext[3]);
    temp[7] = (gf_mult2(ptext[4]) ^ ptext[4]) ^ ptext[5] ^ ptext[6] ^ gf_mult2(ptext[7]);
    temp[11] = (gf_mult2(ptext[8]) ^ ptext[8]) ^ ptext[9] ^ ptext[10] ^ gf_mult2(ptext[11]);
    temp[15] = (gf_mult2(ptext[12]) ^ ptext[12]) ^ ptext[13] ^ ptext[14] ^ gf_mult2(ptext[15]);
    
    for(i = 0; i < TXT_LEN; i++)
        ptext[i] = temp[i]; // copy temporary result
    
    return;
}

unsigned char gf_mult2(unsigned char val)
{
    unsigned char result = 0;
    
    if(val & 0x80) result = (val << 1) ^ 0x1B;
    else result = (val << 1);
    
    return result;
}

void add_key(unsigned char *ptext, unsigned char *round_key)
{
    unsigned int i = 0;
    
    for(i = 0; i < TXT_LEN; i++)
        ptext[i] = ptext[i] ^ round_key[i]; // add key - XOR
    
    return;
}

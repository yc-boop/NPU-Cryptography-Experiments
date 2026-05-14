// include files
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"

// parameters
#define KEY_LEN_BYTE    16  // key length in bytes - 16 * 8 = 128 bits
#define KEY_LEN_WORD    8   // key length in words - 8 * 32 = 256 bits
#define NUM_ROUND_128  10
#define TXT_LEN         16  // 16 * 8 = 128 bits
#define NUM_MASK        16  // 16 constant mask numbers
#define SIZE_SBOX       256 // sbox sie - 256 bytes
#define MIX_STR         80
#define NUM_ROUND   14 // number of rounds

#define NUM_TEST    5//1024 // number of test to be run

// gloabel memory for the round keys
unsigned char round_key[NUM_ROUND_128 + 1][TXT_LEN], round_key_inv[NUM_ROUND_128 + 1][TXT_LEN]; // initialize to zeros

unsigned char mask[NUM_MASK], offset[NUM_MASK], shuffle0[NUM_MASK],shuffle10[NUM_MASK], maskcomp0[NUM_MASK], maskcomp10[NUM_MASK];; // the constant mask values; // the constant mask values

unsigned char number_byte[4], text[4], f_text[4];//analysis  4 bytes

unsigned char final_key[TXT_LEN];

unsigned char ptext[TXT_LEN], ttext[TXT_LEN],stext[16],ftext[16];// key[KEY_LEN_BYTE];

int status;

union key_convert
{
	unsigned char bytes[KEY_LEN_BYTE];
	unsigned int words[KEY_LEN_WORD];
};

union byte_convert
{
	unsigned char bytes[4];
	unsigned int word;
};

struct Bits8
{
	unsigned b0 : 1, b1 : 1, b2 : 1, b3 : 1, b4 : 1, b5 : 1, b6 : 1, b7 : 1;
};

union CBits8
{
	struct Bits8 bits;
	unsigned char byte;
};

struct Bits16
{
	unsigned b0 : 1, b1 : 1, b2 : 1, b3 : 1, b4 : 1, b5 : 1, b6 : 1, b7 : 1, b8 : 1, b9 : 1, b10 : 1, b11 : 1, b12 : 1, b13 : 1, b14 : 1, b15 : 1;
};

union CBits16
{
	struct Bits16 bits;
	unsigned short int word;
};


enum LOCATION {
	SBOX = 0,
	SHR,
	MIX,
	ADDKEY,
	START,
	STOP,
	EXIT,
	ERROR,
	HELP,
	AES128,
	AES256,
	ROUND9_SBOX,
	ROUND9_MIX,
	ROUND8_SBOX,
	ROUND8_MIX
};
/**************************************aes128_rsm_dpv2.c***************************************/
void aes128_rsm2(unsigned char *key, unsigned char *ptext, unsigned char *offset);
void aes128_rsm2_fault(unsigned char *key, unsigned char *ptext, unsigned char *offset);
void add_eor(unsigned char *ptext, unsigned char *ttext);
void key_expansion(unsigned char *key);
void expand_key_128(union key_convert key_in, union key_convert *key_out, unsigned char rcon);
void roundkey_mask(unsigned char *key_128, unsigned char *mask, unsigned char *offset);
void rsm_sub_bytes(unsigned char *ptext, unsigned char *offset, unsigned int round);
void shiftrows(unsigned char *ptext);
void mix_columns(unsigned char *ptext);
void maskcomp(unsigned int round, unsigned char *offset);
unsigned char gf_mult2(unsigned char val);
unsigned char sbox(unsigned char index);
unsigned char masked_sboxes(unsigned int index);
void sbox4(unsigned int inword, unsigned int *outword);

/**************************************aes128_rsm_dec_dpv2.c***************************************/
void inv_shift_rows(unsigned char *ptext);
void inv_mix_columns(unsigned char *ptext);
unsigned char gf_mult4(unsigned char val);
unsigned char gf_mult8(unsigned char val);
unsigned char gf_mult14(unsigned char val);
void rsm_sub_bytes_dec(unsigned char *ptext, unsigned char *offset,unsigned int round);
void aes128_rsm2_dec(unsigned char *key, unsigned char *ptext, unsigned char *offset);

/**************************************function.c***************************************/
void rand_data(unsigned char *ptext, unsigned char *ptext_obfus);
void rand_paramter(unsigned char *paramter);
void print_ptext(unsigned char *ptext);
void output_data(unsigned char *ptext, unsigned char *ptext_obfus, int round_number, int op);
void del_file(int round_number, int op);
void get_analysis_byte(unsigned char *ptext, unsigned char *number_byte, unsigned char *text);
void get_key(unsigned char *number, int key1, int key2, int key3, int key4);
void get_cipher(char *out, char *f_out, unsigned char *ptext, unsigned char *ttext, unsigned char *offset);
unsigned char char2hex(char ch);
void guess_byte(unsigned char *number_byte, unsigned char byte1, unsigned char byte2, unsigned char byte3, unsigned char byte4);
unsigned char rsm_sub_bytes_dec_att(unsigned char number_byte, unsigned char ptext, unsigned char *offset);
/**************************************fault_attack.c***************************************/
void round9_sbox(int position, unsigned char *number_byte, unsigned char *ptext, unsigned char *ttext, unsigned char *key, char *str,unsigned char *offset);
void round9_mix(int position, unsigned char *number_byte, unsigned char *ptext, unsigned char *ttext, unsigned char *key, char *str, unsigned char *offset);
void key_search_key123(unsigned char *key, char *str, unsigned char *number_byte, unsigned char *ptext, unsigned char *ttext, unsigned char *offset);
void key_search_key4(char *str, unsigned int key1, unsigned int key2, unsigned int key3, unsigned char *number, unsigned char *number_type, unsigned char *ptext, unsigned char *ttext, unsigned char *offset);

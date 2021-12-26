/*  AES256_encrypted_functions.cpp
 *
 *  Copyright (c) 2021, Mattia Cacciatore <cacciatore1995@hotmail.it>
 *  All rights reserved.
 *
 *  AES256 is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation, either version 2.1
 *  of the License, or (at your option) any later version.
 *
 *  AES256 is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with AES256.
 *  If not, see <http://www.gnu.org/licenses/>.
 */
#include "AES256_encrypted.h"
/*------------------------------------------------------------------------------------------------------------------------------*/
//  GLOBAL MATRIX - ARRAYS
/*------------------------------------------------------------------------------------------------------------------------------*/
// It should be 32 byte length --> 256 bit. 
// AES 256 official document test pag. 42 FIPS.
const unsigned char PrivateKey[KEY_SIZE] = { 
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
// Galois Field (2^8) - Rijndael Substitution Box. Easier to read.
const unsigned char s_box[BOX_SIZE][BOX_SIZE] = {
//     0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, // 0
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, // 1
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, // 2
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, // 3
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, // 4
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, // 5
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, // 6
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, // 7
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, // 8
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, // 9
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, // a
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, // b
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, // c
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, // d
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, // e
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}  // f
};
// The round constant word array. There're only 15 values for AES 256.
const unsigned char r_con[BOX_SIZE] = { 
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
};
// Look up table with results of Galois multiplication by 10_{base 2} modulo 100011011_{base 2}.
const unsigned char mul2[TABLE_SIZE] = {
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
    0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
    0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
    0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
    0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
    0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
    0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
    0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
    0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
    0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
};
// Look up table with results of Galois multiplication by 11_{base 2} modulo 100011011_{base 2}.
const unsigned char mul3[TABLE_SIZE] = { 
    0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
    0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
    0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
    0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
    0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
    0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
    0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
    0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
    0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
    0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
    0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
    0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
    0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
    0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
    0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
    0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a
};
/*------------------------------------------------------------------------------------------------------------------------------*/
//  HELPER FUNCTIONS
/*------------------------------------------------------------------------------------------------------------------------------*/
// First step of Key expansion, it rotates one column.
void rotate_word(unsigned char word[NUM_BLOCKS]){
    unsigned char tmp;
    // eg.
    // |1F|    |AC|
    // |AC| -> |B7|
    // |B7|    |98|
    // |98|    |1F|
    tmp = word[0];
    for(int i = 0; i < NUM_BLOCKS - 1; ++i){ word[i]= word[i + 1];}
    word[NUM_BLOCKS - 1] = tmp;
}
// Second step of Key expansion, it takes the same column and substitute values with s_box. 
// NOTE: this function is very similar to sub_bytes. They were split for clarity.
void substitute_word(unsigned char word[NUM_BLOCKS]){
    unsigned char c;
    // Rows for that column.
    for(int r = 0, column, row; r < NUM_BLOCKS; ++r){
	// eg. 
	// c = state[0][0] = 0x75 --> 7th row 5th column
	// s_box[7][5] --> 0x9d
	c = word[r];
	column = static_cast<int>(c % 16);
	c -= (c % 16);
	row = 0;
	for(; c >= BOX_SIZE; ++row){ c -= BOX_SIZE;}	
	word[r] = s_box[row][column];
   }	
}
// Third step of Key expansion, it adds the R_con box's round-th value in the first position, 
// 0 in the others in order to execute XOR operations.
void R_con(unsigned char RCon_column[NUM_BLOCKS], const int round){
   // eg.
   // |8c|   |01|   |8d|
   // |75| + |00| = |75|
   // |f7|   |00|   |f7|
   // |aa|   |00|   |aa|

   // It doesn't execute XOR operations for the last 3 positions because XOR 
   // by 0 is equivalent to do nothing.
   RCon_column[0] = static_cast<unsigned char>(RCon_column[0] ^ r_con[round]);
}
// It creates other Nr keys based on the first key (first key = plaintext).
void key_expansion(unsigned char expanded_key[NUM_BLOCKS][NUM_BLOCKS * (NUM_ROUNDS + 1)]){
   // ExpandedKey is a series of columns made of 4 bytes words,
   // 14 rounds require 14 keys + 1 original key --> 14 * 4 + 4 = 60 columns.
   unsigned char tmp[NUM_BLOCKS];
   for(int c = 0, i = 0; i < KEY_SIZE; ++c){
	// Copying Secret Key in the first 8 columns.
	for(int r = 0; r < NUM_BLOCKS; ++r, ++i){ expanded_key[r][c] = PrivateKey[i];}
   }
	
   for(int i = NUM_KEY, round = 1; i < NUM_BLOCKS * (NUM_ROUNDS + 1) ; ++i){
	// Storing previous last word to be processed into tmp array.
	for(int j = 0; j < NUM_BLOCKS; ++j){ tmp[j] = expanded_key[j][i - 1];}
		
	if(i % NUM_KEY == 0){
	   // To obtain the first column of the next round key...
	   rotate_word(tmp);
	   substitute_word(tmp);
	   R_con(tmp, round);
	   ++round;
	}
	// This step is only for AES 256.
	if(NUM_KEY > 6 && i % NUM_KEY == 4) substitute_word(tmp);
	// XOR operations.
	for(int j = 0; j < NUM_BLOCKS; ++j){ expanded_key[j][i] = static_cast<unsigned char>(expanded_key[j][i - NUM_KEY] ^ tmp[j]);}
   }
}
// Rijndael key schedule.
void AES_key_scheduler(const unsigned char expanded_key[NUM_BLOCKS][NUM_BLOCKS * (NUM_ROUNDS + 1)], 
                             unsigned char round_key[NUM_BLOCKS][NUM_BLOCKS], const int round){
   // Copying the round-th key into RoundKey matrix ready to encrypt state matrix.
   for(int c = 0; c < NUM_BLOCKS; ++c){
	for(int r = 0; r < NUM_BLOCKS; ++r){ round_key[r][c] = expanded_key[r][(NUM_BLOCKS * round) + c];}
   }
}
// First step of AES-256 algorithm. It substitute matrix values with Rijndael's s_box values.
void sub_bytes(unsigned char state[NUM_BLOCKS][NUM_BLOCKS]){
   unsigned char c;
   // Rows.
   for(int i = 0, row, column; i < NUM_BLOCKS; ++i){
       // Columns.
       for(int j = 0; j < NUM_BLOCKS; ++j){
	   c = state[i][j];
	   column = static_cast<int>(c % 16);
	   c -= (c % 16);
	   row = 0;
	   for(; c >= BOX_SIZE; ++row){ c -= BOX_SIZE;}
	   state[i][j] = s_box[row][column];
       }
   }
}
// Second step of AES-256 algorithm. It switchs rows between them creating confusion.
void shift_rows(unsigned char state[NUM_BLOCKS][NUM_BLOCKS]){
   unsigned char tmp;
   // Shift starts from second row.
   for(int i = 1; i < NUM_BLOCKS; ++i){
	if(i == 1){ // Second row, shift left by 1 position.
	   tmp = state[i][0];
	   // b4, b5, b6, b7 --> b5, b6, b7, b4.
	   for(int j = 0; j < NUM_BLOCKS - 1; ++j){ state[i][j] = state[i][j + 1];}
	   state[i][NUM_BLOCKS - 1] = tmp;
	}
	else if(i == 2){ // Third row, shift left by 2 positions. In a 4x4 matrix, shifting left
			 // by 2 posisions is equivalent to swap 2 values.
	   tmp = state[i][1];
	   state[i][1] = state[i][3]; // b11 --> b9.
	   state[i][3] = tmp;         // b9 --> b11.
	   tmp = state[i][0];
           state[i][0] = state[i][2]; // b10 --> b8.
	   state[i][2] = tmp;         // b8 --> b10.
	}
	else{ // Fourth row, shift left by 3 positions. In a 4x4 matrix, shifting left 
	      // a row by 3 posisions is equivalent to shift right by 1 position.
	   tmp = state[i][NUM_BLOCKS - 1];
	   // b12, b13, b14, b15 --> b15, b12, b13, b14.
	   for(int j = NUM_BLOCKS - 1; j > 0; --j){ state[i][j] = state[i][j - 1];}	
	   state[i][0] = tmp;
	}
   }
}
// Third step of AES-256 algorithm. It diffuses confusion.
void mix_columns(unsigned char state[NUM_BLOCKS][NUM_BLOCKS]){
   unsigned char tmp[NUM_BLOCKS]; //Helper column.
   for(int c = 0; c < NUM_BLOCKS; ++c){
       // |a1j|   | 2 3 1 1 |   |tmp0j|   |b0j|
       // |a1j| * | 1 2 3 1 | = |tmp1j| = |b1j|
       // |a2j|   | 1 1 2 3 |   |tmp2j|   |b2j|
       // |a3j|   | 3 1 1 2 |   |tmp3j|   |b3j|
	   
       // Column * fixed matrix.	  
       // Addition is performed by XOR.
       // Multiplication is performed by look up tables.
       // static_cast<>() is a safe cast in C++.
	tmp[0] = static_cast<unsigned char>((mul2[state[0][c]]) ^ (mul3[state[1][c]]) ^ (state[2][c]) ^ (state[3][c]));
	tmp[1] = static_cast<unsigned char>((state[0][c]) ^ (mul2[state[1][c]]) ^ (mul3[state[2][c]]) ^ (state[3][c]));
	tmp[2] = static_cast<unsigned char>((state[0][c]) ^ (state[1][c]) ^ (mul2[state[2][c]]) ^ (mul3[state[3][c]]));
	tmp[3] = static_cast<unsigned char>((mul3[state[0][c]]) ^ (state[1][c]) ^ (state[2][c]) ^ (mul2[state[3][c]]));	
	for(int r = 0; r < NUM_BLOCKS; ++r){ state[r][c] = tmp[r];}
   }
}
// Fourth and last step of AES-256 algorithm. It permutes state matrix with roundkey using XOR operator.
void add_round_key(unsigned char state[NUM_BLOCKS][NUM_BLOCKS], const unsigned char round_key[NUM_BLOCKS][NUM_BLOCKS]){
   for(int r = 0, i = 0; r < NUM_BLOCKS; ++r){
	// | s11 s12 s13 s14 |     | r11 r12 r13 r14 |     | se11 se12 se13 se14 |
	// | s21 s22 s23 s24 |  +  | r21 r22 r23 r24 |  =  | se21 se22 se23 se24 |
        // | s31 s32 s33 s34 |     | r31 r32 r33 r34 |     | se31 se32 se33 se34 |
	// | s41 s42 s43 s44 |     | r41 r42 r43 r44 |     | se41 se42 se43 se44 |
	//	 state                  round_key               state encrypted
	for(int c = 0; c < NUM_BLOCKS; ++c, ++i){ state[r][c] = static_cast<unsigned char>(state[r][c] ^ RoundKey[r][c]);} // XOR operation.
   }
}
/*------------------------------------------------------------------------------------------------------------------------------*/
//  FUNCTIONS - AES
/*------------------------------------------------------------------------------------------------------------------------------*/
void encrypt(const unsigned char state_in[TEXT_SIZE], unsigned char state_out[NUM_BLOCKS][NUM_BLOCKS]){
    // State matrix.
    unsigned char state[NUM_BLOCKS][NUM_BLOCKS];
    // Round key matrix.
    unsigned char round_key[NUM_BLOCKS][NUM_BLOCKS];
    // Expanded key matrix.
    unsigned char expanded_key[NUM_BLOCKS][NUM_BLOCKS * (NUM_ROUNDS + 1)];
    
    // Initializing state matrix...
    for(int c = 0, i = 0; c < NUM_BLOCKS; ++c){
    	for(int r = 0; r < NUM_BLOCKS; ++r, ++i){ state[r][c] = state_in[i];}
    }
	
    key_expansion(expanded_key);
    // AESKeyScheduler set appropriate key for that round in RoundKey. First round.
    AES_key_scheduler(expanded_key, round_key, 0);
    add_round_key(state, round_key);
    for(int round = 1; round < NUM_ROUNDS; ++round){
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        AES_key_scheduler(expanded_key, round_key, round);
        add_round_key(state, round_key);
    }
    // Last round.
    sub_bytes(state);
    shift_rows(state);
    AES_key_scheduler(expanded_key, round_key, NUM_ROUNDS);
    add_round_key(state, round_key);
    // Copying encrypted password into output matrix.
    for(int r = 0; r < NUM_BLOCKS; ++r){
    	for(int c = 0; c < NUM_BLOCKS; ++c){ state_out[r][c] = state[r][c];}
    }
}
/*------------------------------------------------------------------------------------------------------------------------------*/
//  OTHER FUNCTIONS 
/*------------------------------------------------------------------------------------------------------------------------------*/
void print_matrix(const unsigned char matrix[NUM_BLOCKS][NUM_BLOCKS]){
	std::cout << "\n";
	for(int c = 0; c < NUM_BLOCKS; ++c){
		for(int r = 0; r < NUM_BLOCKS; ++r){ std::cout << static_cast<unsigned char>(matrix[r][c]);}
	}
	std::cout << "\n\nHex format:\n\n";
	for(int c = 0; c < NUM_BLOCKS; ++c){
		for(int r = 0; r < NUM_BLOCKS; ++r){ std::cout << std::hex << static_cast<int>(matrix[r][c]) << " ";}
	}
	std::cout << "\n";
}

void print_expanded_matrix(const unsigned char matrix[NUM_BLOCKS][NUM_BLOCKS * (NUM_ROUNDS + 1)]){
	for(int r = 0; r < NUM_BLOCKS; ++r){
		std::cout << "\n| ";
		for(int c = 0; c < NUM_BLOCKS * (NUM_ROUNDS + 1); ++c){ std::cout << std::hex << static_cast<int>(matrix[r][c]) << " ";}
		std::cout << "|";
	}
	std::cout << "\n";
}

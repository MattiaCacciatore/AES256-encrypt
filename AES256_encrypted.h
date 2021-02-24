/*
 *  AES256_encrypted.h
 *
 *  Copyright (c) 2021, Mattia Cacciatore <cacciatore1995@hotmail.it>
 *  All rights reserved.
 *
 *	AES256 is free software: you can redistribute it and/or modify
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
#include <iostream>
/*------------------------------------------------------------------------------------------------------------------------------*/
//  MACROS
/*------------------------------------------------------------------------------------------------------------------------------*/
#define BOX_SIZE      16  /*  Size of s_box. */
#define STATE_SIZE    4   /*  Size of state matrix. */
#define KEY_SIZE      32  /*  Size of SecretKey in bytes. 16 --> 128, 24 --> 192, 32 --> 256. */
#define TEXT_SIZE     16  /*  Size of text/message/password. */
#define TABLE_SIZE    256 /*  Size of tables in GF(2^8) implemented as array. */
#define NUM_ROUNDS    14  /*  Number of encrypt round repetitions. 10 --> 128, 12 --> 192, 14 --> 256. */
#define NUM_BLOCKS    4   /*  Number of words/columns in block input like state matrix. */
#define NUM_KEY       8   /*  Number of words/columns in the key. 4 --> 128, 6 --> 192, 8 --> 256. */

namespace aes256{
/*------------------------------------------------------------------------------------------------------------------------------*/
//	FUNCTIONS
/*------------------------------------------------------------------------------------------------------------------------------*/
/*	Encrypt key using AES-256 algorithm. First array input, second matrix output. */
void Encrypt(const unsigned char [TEXT_SIZE], unsigned char [NUM_BLOCKS][NUM_BLOCKS]);
/*	It creates other Nr keys based on the first key (first key = plaintext). */
void KeyExpansion(unsigned char [NUM_BLOCKS][NUM_BLOCKS * (NUM_ROUNDS + 1)]);
/*	Rijndael key schedule. */
void AESKeyScheduler(const unsigned char [NUM_BLOCKS][NUM_BLOCKS * (NUM_ROUNDS + 1)], unsigned char [NUM_BLOCKS][NUM_BLOCKS], const int);
/*	First step of AES-256 algorithm. It substitute matrix values with Rijndael's s_box values. */
void SubBytes(unsigned char [NUM_BLOCKS][NUM_BLOCKS]);
/*  Second step of AES-256 algorithm. It switchs rows between them creating confusion. */
void ShiftRows(unsigned char [NUM_BLOCKS][NUM_BLOCKS]);
/*  Third step of AES-256 algorithm. It diffuses confusion. */
void MixColumns(unsigned char [NUM_BLOCKS][NUM_BLOCKS]);
/*  Fourth and last step of AES-256 algorithm. It permutes state matrix with roundkey using XOR operator. */
void AddRoundKey(unsigned char [NUM_BLOCKS][NUM_BLOCKS], const unsigned char [NUM_BLOCKS][NUM_BLOCKS]);
}
/*------------------------------------------------------------------------------------------------------------------------------*/
//	OTHER FUNCTIONS
/*------------------------------------------------------------------------------------------------------------------------------*/
/*  Print matrix 4 x 4 */
void PrintMatrix(const unsigned char [NUM_BLOCKS][NUM_BLOCKS]);
/*  Print matrix 4 x 68 */
void PrintExpandedMatrix(const unsigned char [NUM_BLOCKS][NUM_BLOCKS * (NUM_ROUNDS + 1)]);

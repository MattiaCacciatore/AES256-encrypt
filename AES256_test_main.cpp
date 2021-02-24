/*
 *  AES256_test_main.c
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
#include"AES256_encrypted.h"

int main()
{
	unsigned char c;
	/*  Message/plaintext/password. */
	unsigned char text[TEXT_SIZE];
	/*  State_out matrix - encrypted message/plaintext/password. */
	unsigned char enc_text[NUM_BLOCKS][NUM_BLOCKS];
	/*  Initializing text field. */
	for(int i = 0; i < TEXT_SIZE; ++i)
		text[i] = 0x00;
	
	std::cout << "Insert your password/text [MAX 16 characters]: ";
	for(int i = 0; i < TEXT_SIZE; ++i)
	{
		c = fgetc(stdin); 
		if(c == '\n' || c == '\0' || c == EOF)
			break;
		
		text[i] = c;
	}
	
	freopen("aes256_test.txt","w",stdout);
	
	aes256::Encrypt(text, enc_text); /*  Magic! Wizard power! */
	
	std::cout << "Plaintext:\n\n";
	for(int i = 0; i < TEXT_SIZE; ++i)
		std::cout << text[i];
	
	std::cout << "\n\nEncrypted text:\n";
	PrintMatrix(enc_text);
	
	return 0;
}

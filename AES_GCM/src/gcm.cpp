#include <stdio.h>
#include <string.h>

#define rfirst(x)    ((unsigned char) (x >> 24 ))
#define rsecond(x)   ((unsigned char) (x >> 16 ))
#define rthird(x)    ((unsigned char) (x >> 8  ))
#define rfourth(x)   ((unsigned char) (x       ))
#define lfirst(x)  (((unsigned char)x) << 24  )
#define lsecond(x) (((unsigned char)x) << 16  )
#define lthird(x)  (((unsigned char)x) << 8   )
#define lfourth(x) (((unsigned char)x)        )

unsigned int redpoly[4] = {0xE1000000, 0x00000000, 0x00000000, 0x00000000}; // Reduction polynomial value for GF multiplication
unsigned int a[4], b[4]; //Inputs for GF multiplication
unsigned int H[4][4];	  // H obatined by encrypting zeroarray with Key
unsigned int y0[4][4], y1[4][4], y2[4][4], y3[4][4], y4[4][4]; // Values of Counter
// Encryted value of counters
unsigned int cipher_y0[4][4];
unsigned int cipher_y1[4][4];
unsigned int cipher_y2[4][4];
unsigned int cipher_y3[4][4];
unsigned int cipher_y4[4][4];
unsigned int auth_a1[4][4]; // Authentication 1
unsigned int result_a1[4]; // Result obtained after GF multiplication of auth1 and H
unsigned int result_f[4]; // Final result obtained after considering all the authenication
unsigned int result_a1_2[4][4]; // 2 D array of result a1
unsigned int result_f_2[4][4]; // 2D array of result f
unsigned int ciphertext1[4][4]; // 1st Cipher Text
unsigned int ciphertext2[4][4]; // 2nd Cipher Text
unsigned int ciphertext3[4][4]; // 3rd Cipher Text
unsigned int ciphertext4[4][4]; // 4nd Cipher Text
unsigned int x_cipher2[4]; // Intermediate output in GHASH stages
unsigned int x_cipher3[4];
unsigned int x_cipher4[4];
unsigned int out_s1[4]; // Output of different stages in GHASH calculation
unsigned int out_s2[4];
unsigned int out_s3[4];
unsigned int out_s4[4];
unsigned int x_len[4]; // XOR with Length
unsigned int len[4][4]; // 2D array for length
unsigned int ghash[4];
unsigned int tag[4];
unsigned int zeroarray[4][4]  = {  {0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00} };
//Value of length for 3 rd Test Case

unsigned int length[4][4]  = { {0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x02},
		{0x00, 0x00, 0x00, 0x00} };

//Value of lenght for 4 th Test Case
/*
unsigned int length[4][4]  = { {0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x01},
		{0x00, 0xa0, 0x00, 0xe0} };*/

void AES_printf (unsigned int AES_StateArray[][4]);
const unsigned char SBox[256] = {
		// 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,   //0
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,   //1
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,   //2
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,   //3
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,   //4
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,   //5
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,   //6
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,   //7
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,   //8
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,   //9
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,   //A
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,   //B
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,   //C
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,   //D
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,   //E
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F

//    W0    W1    W2    W3
//unsigned char CipherText[4][4] = {  {0x39, 0x02, 0xdc, 0x19},
//		{0x25, 0xdc, 0x11, 0x6a},
//		{0x84, 0x09, 0x85, 0x0b},
//		{0x1d, 0xfb, 0x97, 0x32}};

const unsigned char RCon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

#define xTime(x) ((x<<1) ^ ((x & 0x080) ? 0x1b : 0x00))

void encrypt(unsigned PlainText[4][4], unsigned Key[4][4], unsigned CipherText[4][4]) {
	/************************************************
	 ******************Directives********************
	 ************************************************/
#pragma HLS INTERFACE ap_fifo port=PlainText
#pragma HLS INTERFACE ap_fifo port=Key
#pragma HLS INTERFACE ap_fifo port=CipherText

	/************************************************
	 ****************Source Code*********************
	 ************************************************/

	unsigned char StateArray [4][4];
	unsigned char ExpandedKey[11][4][4];
	unsigned char TempKeyCol[4];
	//static int i,j;

	// Encryption Key copied to Expanded Key [0]
	for(int i=0; i<4; i++) {
		for(int j=0; j<4; j++) {
			ExpandedKey[0][i][j] = Key[i][j];
		}
	}

	//	ExpandKey(Key, ExpandedKey);
	for (int i=1; i<11; i++){
		// W3 copied to TempKeyRow with rotation
		TempKeyCol[0]=ExpandedKey[i-1][1][3];
		TempKeyCol[1]=ExpandedKey[i-1][2][3];
		TempKeyCol[2]=ExpandedKey[i-1][3][3];
		TempKeyCol[3]=ExpandedKey[i-1][0][3];

		// sBox applied
		TempKeyCol[0]=SBox[ TempKeyCol[0] ];
		TempKeyCol[1]=SBox[ TempKeyCol[1] ];
		TempKeyCol[2]=SBox[ TempKeyCol[2] ];
		TempKeyCol[3]=SBox[ TempKeyCol[3] ];

		// Rcon applied
		TempKeyCol[0]^=RCon[i-1];

		// XOR
		for(int j=0; j<4; j++){
			TempKeyCol[0] = TempKeyCol[0]^ExpandedKey[i-1][0][j];
			TempKeyCol[1] = TempKeyCol[1]^ExpandedKey[i-1][1][j];
			TempKeyCol[2] = TempKeyCol[2]^ExpandedKey[i-1][2][j];
			TempKeyCol[3] = TempKeyCol[3]^ExpandedKey[i-1][3][j];

			ExpandedKey[i][0][j] = TempKeyCol[0];
			ExpandedKey[i][1][j] = TempKeyCol[1];
			ExpandedKey[i][2][j] = TempKeyCol[2];
			ExpandedKey[i][3][j] = TempKeyCol[3];
		}
	}

	for(int i=0; i<4; i++) {
		for(int j=0; j<4; j++) {
			StateArray[i][j] = PlainText[i][j];
		}
	}

	//	AddRoundKey(ExpandedKey[0], StateArray);
	for(int i=0; i<4; i++)
		for(int j=0; j<4; j++)
			StateArray[i][j] ^= ExpandedKey[0][i][j];

	// Rounds
	forRounds:for(int r=1; r<=10; r++){
		//		SubBytes(StateArray);
		forOPT1b:for(int i=0; i<4; i++)
			forOPT1a:for(int j=0; j<4; j++)
				StateArray[i][j] = SBox[StateArray[i][j]];

		//		ShiftRows(StateArray);
		unsigned char x;
		// Row#1 - rotate 1 column to the left
		x = StateArray[1][0];
		StateArray[1][0] = StateArray[1][1];
		StateArray[1][1] = StateArray[1][2];
		StateArray[1][2] = StateArray[1][3];
		StateArray[1][3] = x;
		// Row#2 - rotate 2 column to the left
		x = StateArray[2][0];
		StateArray[2][0] = StateArray[2][2];
		StateArray[2][2] = x;
		x = StateArray[2][1];
		StateArray[2][1] = StateArray[2][3];
		StateArray[2][3] = x;
		// Row#3 - rotate 3 column to the left
		x = StateArray[3][3];
		StateArray[3][3] = StateArray[3][2];
		StateArray[3][2] = StateArray[3][1];
		StateArray[3][1] = StateArray[3][0];
		StateArray[3][0] = x;

		if(r!=10){
			//			MixColumns(StateArray);
			unsigned char StateArrayTmp[4][4];

			for(int i=0;i<4;i++){
				StateArrayTmp[0][i] =
						xTime(StateArray[0][i])^xTime(StateArray[1][i])^StateArray[1][i]^
						StateArray[2][i]^StateArray[3][i];
				StateArrayTmp[1][i] =
						StateArray[0][i]^xTime(StateArray[1][i])^xTime(StateArray[2][i])^
						StateArray[2][i]^StateArray[3][i];
				StateArrayTmp[2][i] =
						StateArray[0][i]^StateArray[1][i]^xTime(StateArray[2][i])^
						xTime(StateArray[3][i])^StateArray[3][i];
				StateArrayTmp[3][i] =
						xTime(StateArray[0][i])^StateArray[0][i]^StateArray[1][i]^
						StateArray[2][i]^xTime(StateArray[3][i]);
			}

			//			memcpy(StateArray, StateArrayTmp, 4 * 4 * sizeof(unsigned char));
			for(int i=0; i<4; i++) {
				for(int j=0; j<4; j++) {
					StateArray[i][j] = StateArrayTmp[i][j];
				}
			}
		}

		//		AddRoundKey(ExpandedKey[i], StateArray);
		forOPT2b:for(int i=0; i<4; i++)
			forOPT2a:for(int j=0; j<4; j++)
				StateArray[i][j] ^= ExpandedKey[r][i][j];
	}

	for(int i=0; i<4; i++) {
		for(int j=0; j<4; j++) {
			CipherText[i][j] = StateArray[i][j];
		}
	}
}

void gfmult(unsigned int ina[4][4], unsigned int b_2d[4][4], unsigned int result[4]) {

        unsigned int tp_st_r[3], tp_st_l[4]; // Temporary storage during shifting of data

        // Converting the values to be multiplied into 32 bit
        for (int i = 0; i < 4; i++){
        	a[i] = lfirst(ina[0][i]) | lsecond(ina[1][i]) | lthird(ina[2][i]) | lfourth(ina[3][i]);
        	b[i] = lfirst(b_2d[0][i]) | lsecond(b_2d[1][i]) | lthird(b_2d[2][i]) | lfourth(b_2d[3][i]);
        }

        for (int i = 0; i < 128; i++) {
        		// Check if the bit is zero or one
                if (b[0] & 0x80000000){
                		for(int j = 0; j < 4; j++){
                			result[j] = result[j] ^ a[j];
                		}
                }
                //Temporary storage of b data
                for (int l = 0; l < 4; l++){
                	tp_st_l[l] = b[l] ;
                }
                b[3] = b[3] << 1;
                // Left shift of values in b
                for (int k = 0; k < 3; k++){
                	b[k] = ((b[k] << 1)| tp_st_l[k+1] >> 31) & 0xFFFFFFFF;
                }
                unsigned int of;
                //Check if the value is within required range
                of = (a[3] & 0x1);
                // Storage of a's data in temporary variable
                for (int n = 0; n < 3; n++){
                	tp_st_r[n] = a[n] ;
                }

                a[0] = a[0] >> 1;
                // Right shifting of bits in a
                for (int p = 1; p < 4; p++){
                    a[p] = (a[p] >> 1) | (tp_st_r[p-1] << 31);
                }

                // Applying reduction polynomial if the value is not within the range
                if (of){
                	for(int q = 0; q < 4; q++){
                		a[q] = a[q] ^ redpoly[q];
                	}
                }
        }
}

void gcm(unsigned int p1[4][4], unsigned int p2[4][4], unsigned int p3[4][4],unsigned int p4[4][4],
		unsigned int auth1[4], unsigned int auth2[4],unsigned int iv[4][4],	unsigned int key[4][4]){

	//H is obtained
	encrypt(zeroarray, key, H);

	//Setting up counters
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			y0[i][j]=iv[i][j];
			y1[i][j]=iv[i][j];
			y2[i][j]=iv[i][j];
			y3[i][j]=iv[i][j];
			y4[i][j]=iv[i][j];
		}
	}
	// Adding counter bits
	y0[3][3] = 0x01;
	y1[3][3] = 0x02;
	y2[3][3] = 0x03;
	y3[3][3] = 0x04;
	y4[3][3] = 0x05;

	//Encryption obtained from each counter stage
	encrypt(y0, key, cipher_y0);
	encrypt(y1, key, cipher_y1);
	encrypt(y2, key, cipher_y2);
	encrypt(y3, key, cipher_y3);
	encrypt(y4, key, cipher_y4);

	// Conversion of authentication 1 to 2D array

	for(int i = 0; i < 4; i++){
		auth_a1[0][i] = rfirst(auth1[i]);
		auth_a1[1][i] = rsecond(auth1[i]);
		auth_a1[2][i] = rthird(auth1[i]);
		auth_a1[3][i] = rfourth(auth1[i]);
	}

	//GF Multiplication of authentication 1 and H
	gfmult(auth_a1, H, result_a1);

	//Presence of authentication 2 is checked
	if(auth2[0] != 0x00000000){
		for(int i = 0; i < 4; i++){
			result_a1[i] = result_a1[i] ^ auth2[i];
		}

		for(int i = 0; i < 4; i++){
			result_a1_2[0][i] = rfirst(result_a1[i]);
			result_a1_2[1][i] = rsecond(result_a1[i]);
			result_a1_2[2][i] = rthird(result_a1[i]);
			result_a1_2[3][i] = rfourth(result_a1[i]);
		}

		//GF multiplication of result and H
		gfmult(result_a1_2, H, result_f);
	}
	else{
		for(int i = 0; i < 4; i++){
			result_f[i] = result_a1[i];
		}
	}

	//Conversion of result_f into two D array
	for(int i = 0; i < 4; i++){
		result_f_2[0][i] = rfirst(result_f[i]);
		result_f_2[1][i] = rsecond(result_f[i]);
		result_f_2[2][i] = rthird(result_f[i]);
		result_f_2[3][i] = rfourth(result_f[i]);
	}

    //CipherText generation 0-4
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < 4; j++){
			ciphertext1[i][j] = cipher_y1[i][j] ^ p1[i][j];
			ciphertext2[i][j] = cipher_y2[i][j] ^ p2[i][j];
			ciphertext3[i][j] = cipher_y3[i][j] ^ p3[i][j];
			ciphertext4[i][j] = cipher_y4[i][j] ^ p4[i][j];
		}
	}

	if((p4[0][3] == 0x00) && (p4[1][3] == 0x00) && (p4[2][3] == 0x00) && (p4[3][3] == 0x00)){
		for(int i = 0; i < 4; i++)
			ciphertext4[i][3] = 0x00;
	}

	//Ciphertexts
	printf("Ciphertext 1: \n");
	AES_printf(ciphertext1);
	printf("Ciphertext 2: \n");
	AES_printf(ciphertext2);
	printf("Ciphertext 3: \n");
	AES_printf(ciphertext3);
	printf("Ciphertext 4: \n");
	AES_printf(ciphertext4);

	//XOR ciphertext 1 and the result of authentication 1 and H
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < 4; j++){
			ciphertext1[i][j] = ciphertext1[i][j] ^ result_f_2[i][j];
		}
	}

	//GF multiplication of ciphertext1 and H
	gfmult(ciphertext1, H, out_s1);

	//XOR out_s1 and ciphertext 2
	for(int i=0; i<4; i++)
	x_cipher2[i] = (lfirst(ciphertext2[0][i]) | lsecond(ciphertext2[1][i]) | lthird(ciphertext2[2][i]) | lfourth(ciphertext2[3][i])) ^ out_s1[i];

	for(int i = 0; i < 4; i++){
		ciphertext2[0][i] = rfirst(x_cipher2[i]);
		ciphertext2[1][i] = rsecond(x_cipher2[i]);
		ciphertext2[2][i] = rthird(x_cipher2[i]);
		ciphertext2[3][i] = rfourth(x_cipher2[i]);
	}

	//GF multiplication of ciphertext2 and H
	gfmult(ciphertext2, H, out_s2);

	//XOR out_s2 and Cipher text 3
	for(int i=0;i <4; i++)
	x_cipher3[i] = (lfirst(ciphertext3[0][i]) | lsecond(ciphertext3[1][i]) | lthird(ciphertext3[2][i]) | lfourth(ciphertext3[3][i])) ^ out_s2[i];

	for(int i = 0; i < 4; i++){
		ciphertext3[0][i] = rfirst(x_cipher3[i]);
		ciphertext3[1][i] = rsecond(x_cipher3[i]);
		ciphertext3[2][i] = rthird(x_cipher3[i]);
		ciphertext3[3][i] = rfourth(x_cipher3[i]);
	}

	//GF multiplication of ciphertext3 and H
	gfmult(ciphertext3, H, out_s3);

	//XOR of out_s3 and ciphertext 4

	for(int i=0;i<4;i++)
	x_cipher4[i] = (lfirst(ciphertext4[0][i]) | lsecond(ciphertext4[1][i]) | lthird(ciphertext4[2][i]) | lfourth(ciphertext4[3][i])) ^ out_s3[i];

	for(int i = 0; i < 4; i++){
		ciphertext4[0][i] = rfirst(x_cipher4[i]);
		ciphertext4[1][i] = rsecond(x_cipher4[i]);
		ciphertext4[2][i] = rthird(x_cipher4[i]);
		ciphertext4[3][i] = rfourth(x_cipher4[i]);
	}

	//GF multiplication of ciphertext4 and H
	gfmult(ciphertext4, H, out_s4);

	//XOR of out_s4 and length
	for(int i=0;i<4;i++)
	x_len[i] = (lfirst(length[0][i]) | lsecond(length[1][i]) | lthird(length[2][i]) | lfourth(length[3][i])) ^ out_s4[i];

	for(int i = 0; i < 4; i++){
		len[0][i] = rfirst(x_len[i]);
		len[1][i] = rsecond(x_len[i]);
		len[2][i] = rthird(x_len[i]);
		len[3][i] = rfourth(x_len[i]);
	}

	gfmult(len, H, ghash);

	//XOR of length and GHASH
	for(int i = 0; i < 4; i++){
		tag[i] = (lfirst(cipher_y0[0][i]) | lsecond(cipher_y0[1][i]) | lthird(cipher_y0[2][i]) | lfourth(cipher_y0[3][i])) ^ ghash[i];
	}
	printf("Tag = %x %x %x %x\n", tag[0], tag[1], tag[2], tag[3]);
}



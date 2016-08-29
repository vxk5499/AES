
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



const unsigned char RCon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

#define xTime(x) ((x<<1) ^ ((x & 0x080) ? 0x1b : 0x00))

#define first(x)		((unsigned char) (x >> 24))
#define second(x)		((unsigned char) (x >> 16))
#define third(x)		((unsigned char) (x >>  8))
#define fourth(x)		((unsigned char) (x		 ))

#define toFirst(x)		(((unsigned char)x) << 24)
#define toSecond(x)		(((unsigned char)x) << 16)
#define toThird(x)		(((unsigned char)x) <<  8)
#define toFourth(x)		(((unsigned char)x)		 )

void encrypt(unsigned int PlainText[4], unsigned int Key[4], unsigned int CipherText[4]) {


	unsigned int StateArray [4];
	unsigned int ExpandedKey[11][4];

	unsigned int TempKeyCol;
	unsigned int TempCol[4];
	//static int i,j;

	// Encryption Key copied to Expanded Key [0]
	for(int i=0; i<4; i++) {
		ExpandedKey[0][i] = Key[i];
	}

	for (int i=1; i<11; i++)
	{
		TempKeyCol = ((SBox[fourth(ExpandedKey[i-1][1])] ^ RCon[i-1]) << 24)
							| (SBox[fourth(ExpandedKey[i-1][2])] << 16)
							| (SBox[fourth(ExpandedKey[i-1][3])] << 8)
							| (SBox[fourth(ExpandedKey[i-1][0])]);

		TempCol[0] = (toFirst(first(TempKeyCol) ^ (first(ExpandedKey[i-1][0]))))
							| (toSecond(second(TempKeyCol) ^ (first(ExpandedKey[i-1][1]))))
							| (toThird(third(TempKeyCol) ^ (first(ExpandedKey[i-1][2]))))
							| (toFourth(fourth(TempKeyCol) ^ (first(ExpandedKey[i-1][3]))));

		TempCol[1] = (toFirst(first(TempCol[0]) ^ (second(ExpandedKey[i-1][0]))))
							| (toSecond(second(TempCol[0]) ^ (second(ExpandedKey[i-1][1]))))
							| (toThird(third(TempCol[0]) ^ (second(ExpandedKey[i-1][2]))))
							| (toFourth(fourth(TempCol[0]) ^ (second(ExpandedKey[i-1][3]))));

		TempCol[2] = (toFirst(first(TempCol[1]) ^ (third(ExpandedKey[i-1][0]))))
							| (toSecond(second(TempCol[1]) ^ (third(ExpandedKey[i-1][1]))))
							| (toThird(third(TempCol[1]) ^ (third(ExpandedKey[i-1][2]))))
							| (toFourth(fourth(TempCol[1]) ^ (third(ExpandedKey[i-1][3]))));

		TempCol[3] = (toFirst(first(TempCol[2]) ^ (fourth(ExpandedKey[i-1][0]))))
							| (toSecond(second(TempCol[2]) ^ (fourth(ExpandedKey[i-1][1]))))
							| (toThird(third(TempCol[2]) ^ (fourth(ExpandedKey[i-1][2]))))
							| (toFourth(fourth(TempCol[2]) ^ (fourth(ExpandedKey[i-1][3]))));

		ExpandedKey[i][0] = (toFirst(first(TempCol[0]))) | (toSecond(first(TempCol[1])))
									| (toThird(first(TempCol[2]))) | (toFourth(first(TempCol[3])));
		ExpandedKey[i][1] = (toFirst(second(TempCol[0]))) | (toSecond(second(TempCol[1])))
									| (toThird(second(TempCol[2]))) | (toFourth(second(TempCol[3])));
		ExpandedKey[i][2] = (toFirst(third(TempCol[0]))) | (toSecond(third(TempCol[1])))
									| (toThird(third(TempCol[2]))) | (toFourth(third(TempCol[3])));
		ExpandedKey[i][3] = (toFirst(fourth(TempCol[0]))) | (toSecond(fourth(TempCol[1])))
									| (toThird(fourth(TempCol[2]))) | (toFourth(fourth(TempCol[3])));
	}

	for(int i=0; i<4; i++) {
		StateArray[i] = PlainText[i];
	}

	//	AddRoundKey(ExpandedKey[0], StateArray);
	for(int i=0; i<4; i++)
		StateArray[i] ^= ExpandedKey[0][i];

	// Rounds
	for(int r=1; r<=10; r++){
		//SubBytes & ShiftRows
		int temp1, temp2;
		//Row #0 - simple substitute with values from SBox
		StateArray[0] = (SBox[first(StateArray[0])] << 24)
							| (SBox[second(StateArray[0])] << 16)
							| (SBox[third(StateArray[0])] << 8)
							| (SBox[fourth(StateArray[0])]);

		//Row #1 - substitute and rotate 1 column to the left
		StateArray[1] = (SBox[first(StateArray[1])] << 24)
							| (SBox[second(StateArray[1])] << 16)
							| (SBox[third(StateArray[1])] << 8)
							| (SBox[fourth(StateArray[1])]);
		temp1 = first(StateArray[1]);
		temp2 = StateArray[1] << 8;
		StateArray[1] = temp2 | temp1;

		//Row #2 - substitute and rotate 2 columns to the left
		StateArray[2] = (SBox[first(StateArray[2])] << 24)
							| (SBox[second(StateArray[2])] << 16)
							| (SBox[third(StateArray[2])] << 8)
							| (SBox[fourth(StateArray[2])]);
		temp1 = (first(StateArray[2]) << 8) | second(StateArray[2]);
		temp2 = StateArray[2] << 16;
		StateArray[2] = temp2 | temp1;

		//Row #3 - substitute and rotate 3 columns to the left
		StateArray[3] = (SBox[first(StateArray[3])] << 24)
							| (SBox[second(StateArray[3])] << 16)
							| (SBox[third(StateArray[3])] << 8)
							| (SBox[fourth(StateArray[3])]);
		temp1 = (first(StateArray[3]) << 16) | (second(StateArray[3]) << 8) | third(StateArray[3]);
		temp2 = StateArray[3] << 24;
		StateArray[3] = temp2 | temp1;

		if(r!=10){
			//			MixColumns(StateArray);
			unsigned int StateArrayTmp[4];
			int temp1, temp2, temp3, temp4;

			//*** Col 0 ***
			//row 0
			temp1 = toFirst((unsigned char)(xTime(first(StateArray[0])) ^ xTime(first(StateArray[1]))
					^ (first(StateArray[1])) ^ (first(StateArray[2])) ^ (first(StateArray[3]))));

			//row 1
			temp2 = toSecond((unsigned char)((first(StateArray[0])) ^ xTime(first(StateArray[1]))
					^ xTime(first(StateArray[2])) ^ (first(StateArray[2])) ^ (first(StateArray[3]))));

			//row 2
			temp3 = toThird((unsigned char)((first(StateArray[0])) ^ (first(StateArray[1]))
					^ xTime(first(StateArray[2])) ^ xTime(first(StateArray[3])) ^ (first(StateArray[3]))));

			//row 3
			temp4 = toFourth((unsigned char)(xTime(first(StateArray[0])) ^ (first(StateArray[0]))
					^ (first(StateArray[1])) ^ (first(StateArray[2])) ^ xTime(first(StateArray[3]))));
			StateArrayTmp[0] = temp1 | temp2 | temp3 | temp4;

			//*** Col 1 ***
			//row 0
			temp1 = toFirst((unsigned char)(xTime(second(StateArray[0])) ^ xTime(second(StateArray[1]))
					^ (second(StateArray[1])) ^ (second(StateArray[2])) ^ (second(StateArray[3]))));

			//row 1
			temp2 = toSecond((unsigned char)((second(StateArray[0])) ^ xTime(second(StateArray[1]))
					^ xTime(second(StateArray[2])) ^ (second(StateArray[2])) ^ (second(StateArray[3]))));

			//row 2
			temp3 = toThird((unsigned char)((second(StateArray[0])) ^ (second(StateArray[1]))
					^ xTime(second(StateArray[2])) ^ xTime(second(StateArray[3])) ^ (second(StateArray[3]))));

			//row 3
			temp4 = toFourth((unsigned char)(xTime(second(StateArray[0])) ^ (second(StateArray[0]))
					^ (second(StateArray[1])) ^ (second(StateArray[2])) ^ xTime(second(StateArray[3]))));
			StateArrayTmp[1] = temp1 | temp2 | temp3 | temp4;

			//*** Col 2 ***
			//row 0
			temp1 = toFirst((unsigned char)(xTime(third(StateArray[0])) ^ xTime(third(StateArray[1]))
					^ (third(StateArray[1])) ^ (third(StateArray[2])) ^ (third(StateArray[3]))));

			//row 1
			temp2 = toSecond((unsigned char)((third(StateArray[0])) ^ xTime(third(StateArray[1]))
					^ xTime(third(StateArray[2])) ^ (third(StateArray[2])) ^ (third(StateArray[3]))));

			//row 2
			temp3 = toThird((unsigned char)((third(StateArray[0])) ^ (third(StateArray[1]))
					^ xTime(third(StateArray[2])) ^ xTime(third(StateArray[3])) ^ (third(StateArray[3]))));

			//row 3
			temp4 = toFourth((unsigned char)(xTime(third(StateArray[0])) ^ (third(StateArray[0]))
					^ (third(StateArray[1])) ^ (third(StateArray[2])) ^ xTime(third(StateArray[3]))));
			StateArrayTmp[2] = temp1 | temp2 | temp3 | temp4;

			//*** Col 3 ***
			//row 0
			temp1 = toFirst((unsigned char)(xTime(fourth(StateArray[0])) ^ xTime(fourth(StateArray[1]))
					^ (fourth(StateArray[1])) ^ (fourth(StateArray[2])) ^ (fourth(StateArray[3]))));

			//row 1
			temp2 = toSecond((unsigned char)((fourth(StateArray[0])) ^ xTime(fourth(StateArray[1]))
					^ xTime(fourth(StateArray[2])) ^ (fourth(StateArray[2])) ^ (fourth(StateArray[3]))));

			//row 2
			temp3 = toThird((unsigned char)((fourth(StateArray[0])) ^ (fourth(StateArray[1]))
					^ xTime(fourth(StateArray[2])) ^ xTime(fourth(StateArray[3])) ^ (fourth(StateArray[3]))));

			//row 3
			temp4 = toFourth((unsigned char)(xTime(fourth(StateArray[0])) ^ (fourth(StateArray[0]))
					^ (fourth(StateArray[1])) ^ (fourth(StateArray[2])) ^ xTime(fourth(StateArray[3]))));
			StateArrayTmp[3] = temp1 | temp2 | temp3 | temp4;

			//Copy StateArrayTmp to StateArray
			StateArray[0] = toFirst(first(StateArrayTmp[0])) | toSecond(first(StateArrayTmp[1]))
												| toThird(first(StateArrayTmp[2])) | toFourth(first(StateArrayTmp[3]));
			StateArray[1] = toFirst(second(StateArrayTmp[0])) | toSecond(second(StateArrayTmp[1]))
												| toThird(second(StateArrayTmp[2])) | toFourth(second(StateArrayTmp[3]));
			StateArray[2] = toFirst(third(StateArrayTmp[0])) | toSecond(third(StateArrayTmp[1]))
												| toThird(third(StateArrayTmp[2])) | toFourth(third(StateArrayTmp[3]));
			StateArray[3] = toFirst(fourth(StateArrayTmp[0])) | toSecond(fourth(StateArrayTmp[1]))
												| toThird(fourth(StateArrayTmp[2])) | toFourth(fourth(StateArrayTmp[3]));
		}

		//		AddRoundKey(ExpandedKey[i], StateArray);
		for(int i=0; i<4; i++)
			StateArray[i] ^= ExpandedKey[r][i];
	}

	for(int i=0; i<4; i++) {
		CipherText[i] = StateArray[i];
	}
}

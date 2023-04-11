module encrypt.aes;

import core.stdc.string: memset, memcpy; // CBC mode, for memset

version = AES128;
//version = AES192
//version = AES256

///The number of columns comprising a state in AES. This is a constant in AES.
enum Nb = 4;

///Block length in bytes. AES only works with blocks of this size.
enum AES_BLOCKLEN = Nb * Nb;

version(AES256){
	enum AES_KEYLEN = 32;
	enum AES_keyExpSize = 240;
	enum Nk = 8;
	enum Nr = 14;
}else version(AES192){
	enum AES_KEYLEN = 24;
	enum AES_keyExpSize = 208;
	enum Nk = 6;
	enum Nr = 12;
}else version(AES128){
	enum AES_KEYLEN = 16; ///Key length in bytes.
	enum AES_keyExpSize = 176;
	enum Nk = 4; ///The number of 32-bit words in a key.
	enum Nr = 10; ///The number of rounds in AES Cipher.
}

struct AES_ctx{
	ubyte[AES_keyExpSize] RoundKey;
	ubyte[AES_BLOCKLEN] Iv;
}

///An array holding the intermediate results during decryption.
alias state_t = ubyte[Nb][Nb];

private:

const(ubyte)[256] sbox = [
//	  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
];

const(ubyte)[256] rsbox = [
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
];

/**
Contains the values given by x to the power (i-1) being
powers of x (x is denoted as {02}) in the field GF(2^8)
*/
const(ubyte)[11] Rcon = [0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

///Produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(ubyte[] RoundKey, const ubyte[] Key){
	uint i, j, k;
	ubyte[4] tempa; // Used for the column/row operations
	
	// The first round key is the key itself.
	for(i = 0; i < Nk; ++i){
		RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
		RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
		RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
		RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
	}
	
	// All other round keys are found from the previous round keys.
	for(i = Nk; i < Nb * (Nr + 1); ++i){
		k = (i - 1) * 4;
		tempa[0]=RoundKey[k + 0];
		tempa[1]=RoundKey[k + 1];
		tempa[2]=RoundKey[k + 2];
		tempa[3]=RoundKey[k + 3];
		
		if(i % Nk == 0){
			// This function shifts the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
			
			// Function RotWord()
			{
				const ubyte u8tmp = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = u8tmp;
			}
			
			// SubWord() is a function that takes a four-byte input word and 
			// applies the S-box to each of the four bytes to produce an output word.
			
			// Function Subword()
			{
				tempa[0] = sbox[tempa[0]];
				tempa[1] = sbox[tempa[1]];
				tempa[2] = sbox[tempa[2]];
				tempa[3] = sbox[tempa[3]];
			}
			
			tempa[0] = tempa[0] ^ Rcon[i/Nk];
		}
		version(AES256){
		if(i % Nk == 4){
			// Function Subword()
			{
				tempa[0] = sbox[tempa[0]];
				tempa[1] = sbox[tempa[1]];
				tempa[2] = sbox[tempa[2]];
				tempa[3] = sbox[tempa[3]];
			}
		}
		}
		j = i * 4; k = (i - Nk) * 4;
		RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
		RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
		RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
		RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	}
}

/**
Adds the round key to state.
The round key is added to the state by an XOR function.
*/
void AddRoundKey(ubyte round, ref state_t state, const(ubyte)[] RoundKey){
	ubyte i, j;
	for(i = 0; i < 4; ++i){
		for(j = 0; j < 4; ++j){
			state[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
		}
	}
}

///Substitutes the values in the state matrix with values in an S-box.
void SubBytes(ref state_t state){
	ubyte i, j;
	for(i = 0; i < 4; ++i){
		for(j = 0; j < 4; ++j){
			state[j][i] = sbox[state[j][i]];
		}
	}
}

/**
Shifts the rows in the state to the left.
Each row is shifted with different offset.
Offset = row number, so the first row is not shifted.
*/
void ShiftRows(ref state_t state){
	ubyte temp;
	
	// Rotate first row 1 columns to left
	temp        = state[0][1];
	state[0][1] = state[1][1];
	state[1][1] = state[2][1];
	state[2][1] = state[3][1];
	state[3][1] = temp;
	
	// Rotate second row 2 columns to left
	temp        = state[0][2];
	state[0][2] = state[2][2];
	state[2][2] = temp;
	
	temp        = state[1][2];
	state[1][2] = state[3][2];
	state[3][2] = temp;
	
	// Rotate third row 3 columns to left
	temp        = state[0][3];
	state[0][3] = state[3][3];
	state[3][3] = state[2][3];
	state[2][3] = state[1][3];
	state[1][3] = temp;
}

ubyte xtime(ubyte x){
	return cast(ubyte)((x<<1) ^ (((x>>7) & 1) * 0x1B));
}

///Mixes the columns of the state matrix.
void MixColumns(ref state_t state){
	ubyte i;
	ubyte Tmp, Tm, t;
	for(i = 0; i < 4; ++i){
		t   = state[i][0];
		Tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];
		Tm  = state[i][0] ^ state[i][1]; Tm = xtime(Tm); state[i][0] ^= Tm ^ Tmp;
		Tm  = state[i][1] ^ state[i][2]; Tm = xtime(Tm); state[i][1] ^= Tm ^ Tmp;
		Tm  = state[i][2] ^ state[i][3]; Tm = xtime(Tm); state[i][2] ^= Tm ^ Tmp;
		Tm  = state[i][3] ^ t ;          Tm = xtime(Tm); state[i][3] ^= Tm ^ Tmp;
	}
}

///Multiply is used to multiply numbers in the field GF(2^8)
pragma(inline,true) ubyte Multiply(ubyte x, ubyte y){
	return (
		((y>>0 & 1) * x) ^
		((y>>1 & 1) * xtime(x)) ^
		((y>>2 & 1) * xtime(xtime(x))) ^
		((y>>3 & 1) * xtime(xtime(xtime(x))))
	);
}

/**
Mixes the columns of the state matrix.
The method used to multiply may be difficult to understand for the inexperienced.
Please use the references to gain more information.
*/
void InvMixColumns(ref state_t state){
	int i;
	ubyte a, b, c, d;
	for(i = 0; i < 4; ++i){ 
		a = state[i][0];
		b = state[i][1];
		c = state[i][2];
		d = state[i][3];
		
		state[i][0] = Multiply(a, 0x0E) ^ Multiply(b, 0x0B) ^ Multiply(c, 0x0D) ^ Multiply(d, 0x09);
		state[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0E) ^ Multiply(c, 0x0B) ^ Multiply(d, 0x0D);
		state[i][2] = Multiply(a, 0x0D) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0E) ^ Multiply(d, 0x0B);
		state[i][3] = Multiply(a, 0x0B) ^ Multiply(b, 0x0D) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0E);
	}
}


///Substitutes the values in the state matrix with values in an S-box.
void InvSubBytes(ref state_t state){
	ubyte i, j;
	for(i = 0; i < 4; ++i){
		for(j = 0; j < 4; ++j){
			state[j][i] = rsbox[state[j][i]];
		}
	}
}

void InvShiftRows(ref state_t state){
	ubyte temp;
	
	//rotate first row 1 columns to right
	temp = state[3][1];
	state[3][1] = state[2][1];
	state[2][1] = state[1][1];
	state[1][1] = state[0][1];
	state[0][1] = temp;
	
	//rotate second row 2 columns to right
	temp = state[0][2];
	state[0][2] = state[2][2];
	state[2][2] = temp;
	
	temp = state[1][2];
	state[1][2] = state[3][2];
	state[3][2] = temp;
	
	//rotate third row 3 columns to right
	temp = state[0][3];
	state[0][3] = state[1][3];
	state[1][3] = state[2][3];
	state[2][3] = state[3][3];
	state[3][3] = temp;
}

///The main function that encrypts the PlainText.
void Cipher(ref state_t state, const(ubyte)[] RoundKey){
	ubyte round = 0;
	
	//add the First round key to the state before starting the rounds.
	AddRoundKey(0, state, RoundKey);
	
	/*
	There will be Nr rounds. The first Nr-1 rounds are identical.
	These Nr rounds are executed in the loop below.
	Last one without MixColumns()
	*/
	for(round = 1; ; ++round){
		SubBytes(state);
		ShiftRows(state);
		if(round == Nr){
			break;
		}
		MixColumns(state);
		AddRoundKey(round, state, RoundKey);
	}
	//add round key to last round
	AddRoundKey(Nr, state, RoundKey);
}

void InvCipher(ref state_t state, const(ubyte)[] RoundKey){
	ubyte round = 0;
	
	// Add the First round key to the state before starting the rounds.
	AddRoundKey(Nr, state, RoundKey);
	
	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr rounds are executed in the loop below.
	// Last one without InvMixColumn()
	for(round = (Nr - 1); ; --round){
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(round, state, RoundKey);
		if(round == 0){
			break;
		}
		InvMixColumns(state);
	}

}

void XorWithIv(ref ubyte[AES_BLOCKLEN] buf, const ubyte[AES_BLOCKLEN] Iv){
	//the block in AES is always 128bit no matter the key size
	for(ubyte i = 0; i < AES_BLOCKLEN; ++i){
		buf[i] ^= Iv[i];
	}
}

public:

void AES_init_ctx(AES_ctx* ctx, const ubyte[AES_KEYLEN] key){
	KeyExpansion(ctx.RoundKey, key);
}

void AES_init_ctx_iv(AES_ctx* ctx, const ubyte[AES_KEYLEN] key, const ubyte[AES_BLOCKLEN] iv){
	KeyExpansion(ctx.RoundKey, key);
	memcpy(ctx.Iv.ptr, iv.ptr, AES_BLOCKLEN);
}

void AES_ctx_set_iv(AES_ctx* ctx, const(ubyte)* iv){
	memcpy(ctx.Iv.ptr, iv, AES_BLOCKLEN);
}

void AES_ECB_encrypt(const(AES_ctx)* ctx, ubyte[] buf){
	//the next function call encrypts the PlainText with the Key using AES algorithm.
	Cipher(cast(state_t)buf[0..AES_BLOCKLEN], ctx.RoundKey);
}

void AES_ECB_decrypt(const(AES_ctx)* ctx, ubyte[] buf){
	//the next function call decrypts the PlainText with the Key using AES algorithm.
	InvCipher(cast(state_t)buf[0..AES_BLOCKLEN], ctx.RoundKey);
}

void AES_CBC_encrypt_buffer(AES_ctx* ctx, ubyte* buf, size_t length){
	size_t i;
	ubyte[AES_BLOCKLEN] Iv = ctx.Iv;
	for (i = 0; i < length; i += AES_BLOCKLEN){
		XorWithIv(buf[0..AES_BLOCKLEN], Iv);
		Cipher(cast(state_t)buf[0..AES_BLOCKLEN], ctx.RoundKey);
		Iv = buf[0..AES_BLOCKLEN];
		buf += AES_BLOCKLEN;
	}
	/* store Iv in ctx for next call */
	memcpy(ctx.Iv.ptr, Iv.ptr, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(AES_ctx* ctx, ubyte* buf, size_t length){
	size_t i;
	ubyte[AES_BLOCKLEN] storeNextIv;
	for (i = 0; i < length; i += AES_BLOCKLEN){
		memcpy(storeNextIv.ptr, buf, AES_BLOCKLEN);
		InvCipher(cast(state_t)buf[0..AES_BLOCKLEN], ctx.RoundKey);
		XorWithIv(buf[0..AES_BLOCKLEN], ctx.Iv);
		memcpy(ctx.Iv.ptr, storeNextIv.ptr, AES_BLOCKLEN);
		buf += AES_BLOCKLEN;
	}
}

/**
Symmetrical operation: same function for encrypting as for decrypting.
Note any IV/nonce should never be reused with the same key
*/
void AES_CTR_xcrypt_buffer(AES_ctx* ctx, ubyte* buf, size_t length){
	ubyte[AES_BLOCKLEN] buffer;
	
	size_t i;
	int bi;
	for(i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi){
		if(bi == AES_BLOCKLEN){
			//we need to regen xor compliment in buffer
			memcpy(buffer.ptr, ctx.Iv.ptr, AES_BLOCKLEN);
			Cipher(cast(state_t)buffer,ctx.RoundKey);
			
			//increment Iv and handle overflow
			for(bi = (AES_BLOCKLEN - 1); bi >= 0; --bi){
				//inc will overflow
				if(ctx.Iv[bi] == 255){
					ctx.Iv[bi] = 0;
					continue;
				}
				ctx.Iv[bi] += 1;
				break;
			}
			bi = 0;
		}
		
		buf[i] = (buf[i] ^ buffer[bi]);
	}
}

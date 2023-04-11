module encrypt.aes;

///The number of columns comprising a state in AES.
enum aesCols = 4;

///Block length in bytes. AES only works with blocks of this size.
enum aesBlockSize = aesCols * aesCols;

private{
	const ubyte[256] sbox = [
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
	
	const ubyte[256] rsbox = [
	//	  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
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
	
	nothrow @nogc pure @safe:
	
	/**
	Contains the values given by x to the power (i-1) being
	powers of x (x is denoted as {02}) in the field GF(2^8)
	*/
	const ubyte[11] rcon = [0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
	
	/**
	Shifts the rows in the state to the left.
	Each row is shifted with different offset.
	Offset = row number, so the first row is not shifted.
	*/
	void shiftRows(ref ubyte[aesCols][aesCols] state){
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
	
	ubyte xTime(ubyte x){
		return cast(ubyte)((x<<1) ^ (((x>>7) & 1) * 0x1B));
	}
	
	///Mixes the columns of the state matrix.
	void mixCols(ref ubyte[aesCols][aesCols] state){
		ubyte tmp, tm, t;
		for(ubyte i = 0; i < 4; i++){
			t   = state[i][0];
			tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];
			tm  = state[i][0] ^ state[i][1]; tm = xTime(tm); state[i][0] ^= tm ^ tmp;
			tm  = state[i][1] ^ state[i][2]; tm = xTime(tm); state[i][1] ^= tm ^ tmp;
			tm  = state[i][2] ^ state[i][3]; tm = xTime(tm); state[i][2] ^= tm ^ tmp;
			tm  = state[i][3] ^ t;           tm = xTime(tm); state[i][3] ^= tm ^ tmp;
		}
	}
	
	///Used to multiply numbers in the field GF(2^8).
	pragma(inline,true)
	ubyte mul(ubyte x, ubyte y){
		return (
			((y>>0 & 1) * x) ^
			((y>>1 & 1) * xTime(x)) ^
			((y>>2 & 1) * xTime(xTime(x))) ^
			((y>>3 & 1) * xTime(xTime(xTime(x))))
		);
	}
	
	/**
	Mixes the columns of the state matrix.
	The method used to multiply may be difficult to understand for the inexperienced.
	Please use the references to gain more information.
	*/
	void invMixCols(ref ubyte[aesCols][aesCols] state){
		for(int i = 0; i < 4; i++){ 
			ubyte a = state[i][0];
			ubyte b = state[i][1];
			ubyte c = state[i][2];
			ubyte d = state[i][3];
			
			state[i][0] = mul(a, 0x0E) ^ mul(b, 0x0B) ^ mul(c, 0x0D) ^ mul(d, 0x09);
			state[i][1] = mul(a, 0x09) ^ mul(b, 0x0E) ^ mul(c, 0x0B) ^ mul(d, 0x0D);
			state[i][2] = mul(a, 0x0D) ^ mul(b, 0x09) ^ mul(c, 0x0E) ^ mul(d, 0x0B);
			state[i][3] = mul(a, 0x0B) ^ mul(b, 0x0D) ^ mul(c, 0x09) ^ mul(d, 0x0E);
		}
	}
	
	
	///Substitutes the values in the state matrix with values in an S-box.
	void invSubBytes(ref ubyte[aesCols][aesCols] state){
		for(ubyte i = 0; i < 4; i++){
			for(ubyte j = 0; j < 4; j++){
				state[j][i] = rsbox[state[j][i]];
			}
		}
	}
	
	void invShiftRows(ref ubyte[aesCols][aesCols] state){
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
	
	/**
	Adds the round key to state.
	The round key is added to the state by an XOR function.
	*/
	void addRoundKey(ubyte round, ref ubyte[aesCols][aesCols] state, const ubyte[] roundKey){
		for(ubyte i = 0; i < 4; i++){
			for(ubyte j = 0; j < 4; j++){
				state[i][j] ^= roundKey[(round * aesCols * 4) + (i * aesCols) + j];
			}
		}
	}
	
	///Substitutes the values in the state matrix with values in an S-box.
	void subBytes(ref ubyte[aesCols][aesCols] state){
		for(ubyte i = 0; i < 4; i++){
			for(ubyte j = 0; j < 4; j++){
				state[j][i] = sbox[state[j][i]];
			}
		}
	}
	
	void xorWithIv(ref ubyte[aesBlockSize] buf, const ubyte[aesBlockSize] iv){
		//the block in AES is always 128bit no matter the key size
		for(ubyte i = 0; i < aesBlockSize; i++){
			buf[i] ^= iv[i];
		}
	}
}

struct AES(size_t keyBits)
if(keyBits == 128 || keyBits == 192 || keyBits == 256){
	enum keySize = keyBits / 8; ///Key length in bytes.
	
	static if(keyBits == 256){
		enum keyExpandSize = 240;
		enum Nk = 8;
		enum Nr = 14;
	}else static if(keyBits == 192){
		enum keyExpandSize = 208;
		enum Nk = 6;
		enum Nr = 12;
	}else static if(keyBits == 128){
		enum keyExpandSize = 176;
		enum Nk = 4; ///The number of 32-bit words in a key.
		enum Nr = 10; ///The number of rounds in AES cipher.
	}else static assert(0);
	
	ubyte[keyExpandSize] roundKey;
	ubyte[aesBlockSize] iv;
	
	nothrow @nogc pure @safe:
	
	///Produces cols(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
	this(const ubyte[keySize] key){
		//the first round key is the key itself.
		for(uint i = 0; i < Nk; i++){
			roundKey[(i * 4) + 0] = key[(i * 4) + 0];
			roundKey[(i * 4) + 1] = key[(i * 4) + 1];
			roundKey[(i * 4) + 2] = key[(i * 4) + 2];
			roundKey[(i * 4) + 3] = key[(i * 4) + 3];
		}
	
		//all other round keys are found from the previous round keys.
		for(uint i = Nk; i < aesCols * (Nr + 1); i++){
			uint k = (i - 1) * 4;
			ubyte[4] temp = [
				roundKey[k+0],
				roundKey[k+1],
				roundKey[k+2],
				roundKey[k+3],
			];
		
			if(i % Nk == 0){
				//shift the 4 bytes in a word to the left once.
				//[a0,a1,a2,a3] becomes [a1,a2,a3,a0]
				const temp0 = temp[0];
				temp[0] = temp[1];
				temp[1] = temp[2];
				temp[2] = temp[3];
				temp[3] = temp0;
			
				//apply the S-box to each of the four bytes to produce an output word.
				temp[0] = sbox[temp[0]];
				temp[1] = sbox[temp[1]];
				temp[2] = sbox[temp[2]];
				temp[3] = sbox[temp[3]];
			
				temp[0] = temp[0] ^ rcon[i/Nk];
			}
			static if(keyBits == 256){
			if(i % Nk == 4){
				temp[0] = sbox[temp[0]];
				temp[1] = sbox[temp[1]];
				temp[2] = sbox[temp[2]];
				temp[3] = sbox[temp[3]];
			}
			}
			uint j = i * 4; k = (i - Nk) * 4;
			roundKey[j + 0] = roundKey[k + 0] ^ temp[0];
			roundKey[j + 1] = roundKey[k + 1] ^ temp[1];
			roundKey[j + 2] = roundKey[k + 2] ^ temp[2];
			roundKey[j + 3] = roundKey[k + 3] ^ temp[3];
		}
	}
	
	this(const ubyte[keySize] key, const ubyte[aesBlockSize] iv){
		this(key);
		this.iv[] = iv;
	}
	
	void encryptECB(ref ubyte[aesBlockSize] buf) const{
		//the next function call encrypts the PlainText with the Key using AES algorithm.
		cipher(cast(ubyte[aesCols][aesCols])buf);
	}
	
	void decryptECB(ref ubyte[aesBlockSize] buf) const{
		//the next function call decrypts the PlainText with the Key using AES algorithm.
		invCipher(cast(ubyte[aesCols][aesCols])buf);
	}
	
	void encryptCBC(ref ubyte[] buf){
		size_t i;
		ubyte[aesBlockSize] iv = this.iv;
		for(i = 0; i < buf.length; i += aesBlockSize){
			ubyte[aesBlockSize] bufX = buf[i..i+aesBlockSize];
			xorWithIv(bufX, iv);
			cipher(cast(ubyte[aesCols][aesCols])bufX);
			iv[] = bufX;
			buf[i..i+aesBlockSize] = bufX;
		}
		//store iv in ctx for next call
		this.iv[] = iv;
	}
	
	void decryptCBC(ref ubyte[] buf){
		size_t i;
		ubyte[aesBlockSize] storeNextIv;
		for(i = 0; i < buf.length; i += aesBlockSize){
			ubyte[aesBlockSize] bufX = buf[i..i+aesBlockSize];
			storeNextIv[] = bufX;
			invCipher(cast(ubyte[aesCols][aesCols])bufX);
			xorWithIv(bufX, this.iv);
			this.iv[] = storeNextIv;
			buf[i..i+aesBlockSize] = bufX;
		}
	}
	
	/**
	Symmetrical operation: same function for encrypting as for decrypting.
	Note any IV/nonce should never be reused with the same key
	*/
	void xcryptCTR(ref ubyte[] buf){
		size_t i;
		int bi;
		ubyte[aesBlockSize] bufX;
		for(i = 0, bi = aesBlockSize; i < buf.length; i++, bi++){
			if(bi == aesBlockSize){
				//we need to regen xor compliment in buffer
				bufX = this.iv;
				
				cipher(cast(ubyte[aesCols][aesCols])bufX);
				
				//increment iv and handle overflow
				for(bi = (aesBlockSize - 1); bi >= 0; bi--){
					//inc will overflow
					if(this.iv[bi] == 255){
						this.iv[bi] = 0;
						continue;
					}
					this.iv[bi] += 1;
					break;
				}
				bi = 0;
			}
			
			buf[i] = (buf[i] ^ bufX[bi]);
		}
	}
	
	private:
	
	///The main function that encrypts the PlainText.
	void cipher(ref ubyte[aesCols][aesCols] state) const{
		ubyte round = 0;
		
		//add the First round key to the state before starting the rounds.
		addRoundKey(0, state, roundKey);
		
		/*
		There will be Nr rounds. The first Nr-1 rounds are identical.
		These Nr rounds are executed in the loop below.
		*/
		for(round = 1; ; round++){
			subBytes(state);
			shiftRows(state);
			if(round == Nr){ //the last round doesn't use mixCols()
				break;
			}
			mixCols(state);
			addRoundKey(round, state, roundKey);
		}
		//add round key to last round
		addRoundKey(Nr, state, roundKey);
	}
	
	void invCipher(ref ubyte[aesCols][aesCols] state) const{
		ubyte round = 0;
		
		//add the First round key to the state before starting the rounds.
		addRoundKey(Nr, state, roundKey);
		
		/*
		There will be Nr rounds. The first Nr-1 rounds are identical.
		These Nr rounds are executed in the loop below.
		*/
		for(round = (Nr - 1); ; round--){
			invShiftRows(state);
			invSubBytes(state);
			addRoundKey(round, state, roundKey);
			if(round == 0){ //the last round doesn't use invMixCols()
				break;
			}
			invMixCols(state);
		}
	}
}
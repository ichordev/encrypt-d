module encrypt.pkcs7;

import encrypt.aes;

nothrow @nogc pure @safe{
	bool padPKCS7(B)(ref B buf, size_t dataSize, ubyte mod=aesBlockSize)
	if(is(B: ubyte[]) || is(B BA: BA[n], size_t n)){
		ubyte padByte = cast(ubyte)(mod - (dataSize % mod));
		if(dataSize + padByte > buf.length){
			return false;
		}
		foreach(ref b; buf[dataSize..dataSize+padByte]){
			b = padByte;
		}
		return true;
	}
	
	bool isValidPKCS7(ubyte[] buf, size_t dataSize, ubyte mod=aesBlockSize){
		ubyte expectedPadByte = cast(ubyte)(mod - (dataSize % mod));
		if(dataSize + expectedPadByte > buf.length){
			return false;
		}
		foreach(const b; buf[dataSize..dataSize+expectedPadByte]){
			if(b != expectedPadByte){
				return false;
			}
		}
		return true;
	}
	
	size_t dataSizePKCS7(const ubyte[] buf, ubyte mod=aesBlockSize){
		//test for valid buffer size
		if(buf.length % mod != 0 || buf.length < mod){
			return 0;
		}
		ubyte padVal;
		padVal = buf[$-1];
		
		//test for valid padding value
		if(padVal < 1 || padVal > mod){
			return 0;
		}
		//buffer must be at least padding_value + 1 in size
		if(buf.length < padVal + 1){
			return 0;
		}
		foreach_reverse(const b; buf[$-padVal..$]){
			if(b != padVal){
				return 0;
			}
		}
		return buf.length - padVal;
	}
	
	@trusted unittest{
		enum reportCT = "my super secret thing that needs to remain that way!";
		ubyte[reportCT.length + aesBlockSize - (reportCT.length % aesBlockSize)] report;
		report[0..reportCT.length] = cast(ubyte[])reportCT;
		enum keyCT = "thisIstheKey";
		ubyte[keyCT.length + aesBlockSize - (keyCT.length % aesBlockSize)] key;
		key[0..keyCT.length] = cast(ubyte[])keyCT;
		auto dlen = reportCT.length;
		auto klen = keyCT.length;
		
		assert(!report.isValidPKCS7(dlen));
		assert(!key.isValidPKCS7(klen));
		
		assert(report.padPKCS7(dlen));
		assert(report == [
			0x6D,0x79,0x20,0x73,0x75,0x70,0x65,0x72,0x20,0x73,0x65,0x63,0x72,0x65,0x74,0x20,
			0x74,0x68,0x69,0x6E,0x67,0x20,0x74,0x68,0x61,0x74,0x20,0x6E,0x65,0x65,0x64,0x73,
			0x20,0x74,0x6F,0x20,0x72,0x65,0x6D,0x61,0x69,0x6E,0x20,0x74,0x68,0x61,0x74,0x20,
			0x77,0x61,0x79,0x21,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C
		]);
		assert(key.padPKCS7(klen));
		assert(key == [0x74,0x68,0x69,0x73,0x49,0x73,0x74,0x68,0x65,0x4B,0x65,0x79,0x04,0x04,0x04,0x04]);
		
		assert(report.isValidPKCS7(dlen));
		assert(key.isValidPKCS7(klen));
		
		const ubyte[aesBlockSize] iv = [0x75, 0x52, 0x5F, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, 0x21, 0x21];
		
		auto aes = AES!128(key, iv);
		
		auto reportx = aes.encryptCBC(report);
		assert(reportx);
			
		aes.iv[] = iv;
		
		auto reportd = aes.decryptCBC(reportx);
		assert(reportd);
		
		size_t len = reportd.dataSizePKCS7();
		assert(reportd[0..len] == cast(ubyte[])reportCT);
	}
}

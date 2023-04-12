module encrypt.pkcs7;

int pkcs7_padding_pad_buffer(ubyte* buffer, size_t data_length, size_t buffer_size, ubyte modulus){
	ubyte pad_byte = cast(ubyte)(modulus - (data_length % modulus));
	if(data_length + pad_byte > buffer_size){
		return -pad_byte;
	}
	int i = 0;
	while(i < pad_byte){
		buffer[data_length+i] = pad_byte;
		i++;
	}
	return pad_byte;
}

int pkcs7_padding_valid(ubyte* buffer, size_t data_length, size_t buffer_size, ubyte modulus){
	ubyte expected_pad_byte = cast(ubyte)(modulus - (data_length % modulus));
	if(data_length + expected_pad_byte > buffer_size){
		return 0;
	}
	int i = 0;
	while(i < expected_pad_byte){
		if(buffer[data_length + i] != expected_pad_byte){
			return 0;
		}
		i++;
	}
	return 1;
}

size_t pkcs7_padding_data_length(ubyte* buffer, size_t buffer_size, ubyte modulus){
	//test for valid buffer size
	if(buffer_size % modulus != 0 || buffer_size < modulus){
		return 0;
	}
	ubyte padding_value;
	padding_value = buffer[buffer_size-1];
	//test for valid padding value
	if(padding_value < 1 || padding_value > modulus){
		return 0;
	}
	//buffer must be at least padding_value + 1 in size
	if(buffer_size < padding_value + 1){
		return 0;
	}
	ubyte count = 1;
	buffer_size --;
	for(; count < padding_value; count++){
		buffer_size--;
		if(buffer[buffer_size] != padding_value){
			return 0;
		}
	}
	return buffer_size;
}

unittest{
	import encrypt.aes;
	import std.stdio;
	
	enum reportCT = "my super secret thing that needs to remain that way!";
	ubyte[reportCT.length + aesBlockSize - (reportCT.length % aesBlockSize)] report = cast(ubyte[])reportCT;
	enum keyCT = "thisIstheKey";
	ubyte[keyCT.length + aesBlockSize - (keyCT.length % aesBlockSize)] key = cast(ubyte[])keyCT;
	auto dlen = report.length;
	auto klen = key.length;
	
	int reportPad = pkcs7_padding_pad_buffer(report.ptr, dlen, report.length, aesBlockSize);
	int keyPad = pkcs7_padding_pad_buffer(key.ptr, klen, key.length, aesBlockSize);
	
	printf("The padded STRING in hex is = ");
	for(ubyte i = 0; i < dlen; i++){
		printf("%02X", report[i]);
	}
	printf("\n");
	
	printf("The padded key in hex is = ");
	for(ubyte i = 0; i < klen; i++){
		printf("%02X",key[i]);
	}
	printf("\n");
		
	//in case you want to check if the padding is valid
	int valid = pkcs7_padding_valid(report.ptr, dlen, report.length, aesBlockSize);
	int valid2 = pkcs7_padding_valid(key.ptr, klen, key.length, aesBlockSize);
	writefln("Is the pkcs7 padding valid report = %d | key = %d\n", valid, valid2);
	
	const ubyte[aesBlockSize] iv = [0x75, 0x52, 0x5F, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, 0x21, 0x21];
	
	//start the encryption
	auto aes = AES!128(key, iv);
	
	//encrypt
	auto reportx = aes.encryptCBC(report[0..dlen]);
	printf("the encrypted STRING = ");
	for(ubyte i = 0; i < dlen; i++){
		printf("%02X", reportx[i]);
	}
	printf("\n");
		
	//reset the iv!! important to work!
	aes.iv[] = iv;
	
	//start decryption
	auto reportd = aes.decryptCBC(reportx[0..dlen]);
	
	size_t actualDataLength = pkcs7_padding_data_length(reportd.ptr, dlen, 16);
	printf("The actual data length (without the padding) = %ld\n", actualDataLength);
	
	printf("the decrypted STRING in hex = ");
	for(ubyte i = 0; i < actualDataLength; i++){
		printf("%02X", reportd[i]);
	}
	printf("\n");
}

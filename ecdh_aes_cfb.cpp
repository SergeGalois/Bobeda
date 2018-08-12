// g++ -g3 -ggdb -O0 -DDEBUG ecdh-agree.cpp -o ecdh-agree.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG ecdh-agree.cpp -o ecdh-agree.exe -lcryptopp -lpthread

/*****************************************************
These are the headers for the AES_CFB
****************************************************/

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CFB_Mode;

#include "assert.h"

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AutoSeededX917RNG;
/************************************************/

/*
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;*/

#include <stdexcept>
using std::runtime_error;

/*
#include <cstdlib>
using std::exit;
*/

/*
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AutoSeededX917RNG;
*/

/*
#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CFB_Mode;
*/

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::EC2N;
using CryptoPP::ECDH;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "cryptopp/asn.h"
using namespace CryptoPP::ASN1;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

/****************************************
Headers for Hash Ker Derivation Function
****************************************/
#include "cryptopp/hkdf.h"
using CryptoPP::HKDF;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;
using CryptoPP::SHA1;

/************************************
Header for Hash Message
***********************************/
#include "cryptopp/hmac.h"
using CryptoPP::HMAC;
using CryptoPP::HashVerificationFilter;
using CryptoPP::HashFilter;
/**********************************
Functions
**********************************/

string Hex_Encode(string );
string Hex_Decode(string );
string AES_CFB_Encryptor(string, string, string);
string AES_CFB_Decryptor(string, string , string);
string HKeyDF(CryptoPP::byte*, CryptoPP::byte*, CryptoPP::byte*);


int main(int argc, char** argv) {

    string text = argv[1];
    string str_pubB = argv[2];

    str_pubB = Hex_Decode(str_pubB);

    OID CURVE = secp256r1();
    AutoSeededX917RNG<AES> rng;

    ECDH < ECP >::Domain dhA( CURVE ), dhB( CURVE );
    //ECDH < EC2N >::Domain dhA( CURVE ), dhB( CURVE );

    // Don't worry about point compression. Its amazing that Certicom got
    // a patent for solving an algebraic equation....
    // dhA.AccessGroupParameters().SetPointCompression(true);
    // dhB.AccessGroupParameters().SetPointCompression(true);

    SecByteBlock privA(dhA.PrivateKeyLength()), pubA(dhA.PublicKeyLength());
    dhA.GenerateKeyPair(rng, privA, pubA);
    
    //SecByteBlock privB(dhB.PrivateKeyLength()), pubB(dhB.PublicKeyLength());
    SecByteBlock pubB;//(dhB.PublicKeyLength());
    pubB = SecByteBlock((unsigned char*)str_pubB.c_str(), str_pubB.size()); 
    //dhB.GenerateKeyPair(rng, privB, pubB);


    Integer A;
    A.Decode(pubA.BytePtr(),pubA.SizeInBytes());
    cout << "Public key: " <<std::hex << A << endl;

    SecByteBlock sharedA(dhA.AgreedValueLength());//, sharedB(dhB.AgreedValueLength());


    const bool rtn1 = dhA.Agree(sharedA, privA, pubB);

    Integer a, b;

    a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
    cout << "(A): " << std::hex << a << endl;
    
    string shared;
    HexEncoder hex2(new StringSink(shared));
    hex2.Put(sharedA.data(), sharedA.size());
    hex2.MessageEnd();
    cout<<"(A hex)"<< shared<<endl;

    cout << "Agreed to shared secret" << endl;

	//int aesKeyLength = SHA256::DIGESTSIZE; // 32 bytes = 256 bit key
    //int defBlockSize = AES::BLOCKSIZE;

    /* Calculate a SHA-256 hash over the Diffie-Hellman session key
    SecByteBlock key_for_aes(CryptoPP::SHA256::DIGESTSIZE);
    //SHA256().CalculateDigest(key, secretKeyA, secretKeyA.size()); 
    CryptoPP::SHA256().CalculateDigest(key, sharedA, sharedA.size()); 
    Integer K;
    K.Decode(key.BytePtr(), key.SizeInBytes());
    cout <<std::hex << K <<endl;*/   
    //CryptoPP::byte key_for_aes[SHA256::DIGESTSIZE];
    CryptoPP::byte password[] = "Password";
    CryptoPP::byte salt[32];
    rng.GenerateBlock(salt,32);
    string str_key = HKeyDF((CryptoPP::byte*) sharedA, password, salt);
    cout <<str_key<<endl;

    SecByteBlock iv(AES::BLOCKSIZE);
    
    rng.GenerateBlock(iv, iv.size());
    b.Decode(iv.BytePtr(),iv.size());
    cout<<std::hex << b <<endl;

    /*string str_key;
    HexEncoder hex(new StringSink(str_key));
    hex.Put(key.data(), key.size());
    hex.MessageEnd();*/
    
    string str_iv;
    HexEncoder hex1(new StringSink(str_iv));
    hex1.Put(iv.data(), iv.size());
    hex1.MessageEnd();
    
    string texto_cifrado = AES_CFB_Encryptor(text, str_key, str_iv);
    cout <<texto_cifrado << endl;
    string texto_recuperado = AES_CFB_Decryptor(texto_cifrado, str_key, str_iv); 

    cout <<texto_recuperado << endl;


    return 0;
}


string Hex_Encode(string str_in)
{
    string str_out;

    str_out.clear();
	StringSource(str_in, true,
		new HexEncoder(
			new StringSink(str_out)
		) // HexEncoder
	); // StringSource
    return str_out;
}

string Hex_Decode(string str_in)
{
    string str_out;

    str_out.clear();
	StringSource(str_in, true,
		new HexDecoder(
			new StringSink(str_out)
		) // HexEncoder
	); // StringSource
    return str_out;
}


string AES_CFB_Encryptor(CryptoPP::byte* plain_text, CryptoPP::byte* key, CryptoPP::byte* iv)
{
	AutoSeededRandomPool prng;
    

    //string key_decoded,iv_decoded;

    //key_decoded = Hex_Decode(key);
    //iv_decoded = Hex_Decode(iv);


	string cipher, encoded;


	try
	{
	    //cout << "plain text: " << plain_text << endl;

        //SecByteBlock key_decoded_byte, iv_decoded_byte; 
        //key_decoded_byte = SecByteBlock((unsigned char*)key_decoded.c_str(), key.size());
        //iv_decoded_byte = SecByteBlock((unsigned char*)iv_decoded.c_str(), key.size());

		CFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain_text, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
        )
    );
	/*********************************\
	\*********************************/
    return encoded;
}


string AES_CFB_Encryptor(string plain_text, string key, string iv)
{
	AutoSeededRandomPool prng;
    

    string key_decoded,iv_decoded;

    key_decoded = Hex_Decode(key);
    iv_decoded = Hex_Decode(iv);


	string cipher, encoded;


	try
	{
		//cout << "plain text: " << plain_text << endl;

        SecByteBlock key_decoded_byte, iv_decoded_byte; 
        key_decoded_byte = SecByteBlock((unsigned char*)key_decoded.c_str(), key.size());
        iv_decoded_byte = SecByteBlock((unsigned char*)iv_decoded.c_str(), key.size());

		CFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV((CryptoPP::byte*)key_decoded_byte, sizeof(key_decoded_byte), (CryptoPP::byte*) iv_decoded_byte);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain_text, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	//cout << "cipher text: " << encoded << endl;

    return encoded;

}


string AES_CFB_Decryptor(CryptoPP::byte* ciphered_text, CryptoPP::byte* key, CryptoPP::byte* iv)
{
	AutoSeededRandomPool prng;
    

    //string key_decoded,iv_decoded;

    //key_decoded = Hex_Decode(key);
    //iv_decoded = Hex_Decode(iv);


	string recovered, encoded;


	try
	{
	    //cout << "plain text: " << plain_text << endl;

        //SecByteBlock key_decoded_byte, iv_decoded_byte; 
        //key_decoded_byte = SecByteBlock((unsigned char*)key_decoded.c_str(), key.size());
        //iv_decoded_byte = SecByteBlock((unsigned char*)iv_decoded.c_str(), key.size());

		CFB_Mode< AES >::Decryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(ciphered_text, true, 
			new StreamTransformationFilter(e,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(recovered, true,
		new HexEncoder(
			new StringSink(encoded)
        )
    );
	/*********************************\
	\*********************************/
    return encoded;
}


string AES_CFB_Decryptor(string cipher_text, string key, string iv)
{

    string cipher, recovered;

    cout << cipher_text<<endl;
    
    cipher = Hex_Decode(cipher_text);

    string key_decoded,iv_decoded;

    key_decoded = Hex_Decode(key);
    iv_decoded = Hex_Decode(iv);



	try
	{
        SecByteBlock key_decoded_byte, iv_decoded_byte; 
        key_decoded_byte = SecByteBlock((unsigned char*)key_decoded.c_str(), key.size());
        iv_decoded_byte = SecByteBlock((unsigned char*)iv_decoded.c_str(), key.size());
		
        CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV((CryptoPP::byte*)key_decoded_byte, sizeof(key_decoded_byte), (CryptoPP::byte*) iv_decoded_byte);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource (cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

		//cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return recovered;
}


string HKeyDF(CryptoPP::byte* info, CryptoPP::byte* password, CryptoPP::byte* salt)
{
    //cout<<"Thi has worked"<<endl;
    //CryptoPP::byte password[] ="password";
    size_t plen = strlen((const char*)password);

    //CryptoPP::byte salt[] = "salt";
    size_t slen = strlen((const char*)salt);

    //CryptoPP::byte *info = (CryptoPP::byte*)argv[1];//"HKDF key derivation";
    size_t ilen = strlen((const char*)info);

    //CryptoPP::byte derived[SHA1::DIGESTSIZE];
    CryptoPP::byte derived[SHA256::DIGESTSIZE];
    

    //HKDF<SHA1> hkdf;
    HKDF<SHA256> hkdf;
    hkdf.DeriveKey(derived, sizeof(derived), password, plen, salt, slen, info, ilen);

    string result;
    HexEncoder encoder(new StringSink(result));

    encoder.Put(derived, sizeof(derived));
    encoder.MessageEnd();

    //cout << "Derived: " << result << endl;

    return result;
}

string HMessageAC(string plain_text, CryptoPP::byte* key)
{
	AutoSeededRandomPool prng;

	//SecByteBlock key(32);
	//prng.GenerateBlock(key, key.size());

	//string plain = "HMAC Test";
	string mac, encoded;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	cout << "plain text: " << plain_text << endl;

	/*********************************\
	\*********************************/

	try
	{
		HMAC< SHA256 > hmac(key, sizeof(key));		

		StringSource(plain_text, true, 
			new HashFilter(hmac,
				new StringSink(mac)
			) // HashFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print MAC
	encoded.clear();
	StringSource(mac, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "hmac: " << encoded << endl;


    return encoded;

}
	/*********************************\
	\*********************************/


bool HMessageAC_Verification(string plain_text, string mac, CryptoPP::byte* key) 
{
    bool result = true;
	try
	{
		HMAC< SHA256 > hmac(key, sizeof(key));
		const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

		// Tamper with message
		// plain[0] ^= 0x01;

		// Tamper with MAC
		// mac[0] ^= 0x01;
	
		StringSource(plain_text + mac, true, 
			new HashVerificationFilter(hmac, NULL, flags)
		); // StringSource

		//cout << "Verified message" << endl;
        //result = true;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		//exit(1);
        result = false;
	}

	return result;
}

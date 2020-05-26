/**
* encryption.cpp - The module responsible for working with
* elements of encryption and authentication in the TGN network.
*
*	@mrrva - 2019
*/
#include "include/encryption.hpp"
/**
* Used namespaces and objects.
*/
using namespace std;
/**
* tgnencryption :: new_keys - Generate a key pair
* encryption.
*/
void tgnencryption::new_keys(void)
{
	using tgnstruct::secret_key;
	using tgnstruct::public_key;

	public_key = new unsigned char[HASHSIZE];
	secret_key = new unsigned char[HASHSIZE];

	crypto_box_keypair(public_key, secret_key);
}
/**
* tgnencryption :: pack - Byte array encryption
* for sending to the user.
*
* @text - Pointer to a byte array.
* @key - The public key of the user.
*/
unsigned char *tgnencryption::pack(unsigned char *text,
	unsigned char *key)
{
	unsigned char *buffer = nullptr;
	size_t len;

	if (!text || !key) {
		cout << "[E] tgnencryption::pack.\n";
		return nullptr;
	}

	len = TEXTSIZE + 100 + crypto_box_SEALBYTES;
	buffer = new  unsigned  char [len];
	memset(buffer, 0x00, len);

	crypto_box_seal(buffer, text, TEXTSIZE, key);
	return buffer;
}
/**
* tgnencryption :: unpack - Decrypt a byte array
* for further processing.
*
* @text - Pointer to a byte array.
*/
unsigned char *tgnencryption::unpack(unsigned char *text)
{
	using tgnstruct::secret_key;
	using tgnstruct::public_key;

	unsigned char *buffer = nullptr;
	size_t len;

	if (!text) {
		cout << "[E] tgnencryption::unpack.\n";
		return nullptr;
	}

	len = TEXTSIZE + crypto_box_SEALBYTES;
	buffer = new  unsigned  char [len];
	memset(buffer, 0x00, len);

	if (crypto_box_seal_open(buffer, text, len
		, public_key, secret_key) != 0) {
		cout << "[E] crypto_box_seal_open in "
			<< "tgnencryption::unpack\n";
		return nullptr;
	}

	return buffer;
}


#define BN_DEBUG

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/dh.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void hexprint(unsigned char *printBuf, int len)
{
  int i;
  for(i = 0; i < len; i++)
    {
      printf("%x ", printBuf[i]);
    }
  printf("\n");
}

int crypt(unsigned char* ekey, unsigned int ekeylen, unsigned char* dkey, unsigned int dkeylen, unsigned char* iv, unsigned int ivlen);

int main(int argc, char *argv[])
{
  srand(time(NULL));
  DH *dh1;
  DH *dh2;
  unsigned char *dh_secret1;
  unsigned char *dh_secret2;
  ASN1_STRING *str;
  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"01234567890123456";
  unsigned int ivlen = 16;

  str = ASN1_STRING_new();

  dh1 = DH_generate_parameters(256, 2, NULL, NULL);
  //dh2 = DH_generate_parameters(256, 2, NULL, NULL);

  str->length = i2d_DHparams(dh1, &str->data);

  dh2 = d2i_DHparams(NULL, (const unsigned char **)&str->data, str->length);

  //  memcpy(dh2, dh1, sizeof(*dh1));

  DH_generate_key(dh1);
  DH_generate_key(dh2);

  dh_secret1 = malloc(DH_size(dh1));
  memset(dh_secret1, 0, DH_size(dh1));
  dh_secret2 = malloc(DH_size(dh2));
  memset(dh_secret2, 0, DH_size(dh2));

  DH_compute_key(dh_secret1, dh2->pub_key, dh1);
  DH_compute_key(dh_secret2, dh1->pub_key, dh2);

  printf("Public  Key 1: \n");
  BN_print_fp(stdout, dh1->pub_key);
  printf("\nSecret Key 1: size=%dbit\n", DH_size(dh1)*8);
  hexprint(dh_secret1, DH_size(dh1));
  printf("Public  Key 1: \n");
  BN_print_fp(stdout, dh2->pub_key);
  printf("\nSecret Key 2: size=%dbit\n", DH_size(dh2)*8);
  hexprint(dh_secret2, DH_size(dh2));

  crypt(dh_secret1, DH_size(dh1), dh_secret2, DH_size(dh2), iv, ivlen);

  free(dh_secret1);
  free(dh_secret2);
  DH_free(dh1);
  DH_free(dh2);

  return 0;
}



int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
		  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) 
    return -1;

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    return -1;

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    return -1;
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))  return -1;

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    return -1;

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    return -1;
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))  return -1;
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}


int crypt(unsigned char* ekey, unsigned int ekeylen, unsigned char* dkey, unsigned int dkeylen, unsigned char* iv, unsigned int ivlen)
{
  /* Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  /* A 256 bit key */
  //  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

  /* A 128 bit IV */
  // unsigned char *iv = (unsigned char *)"01234567890123456";

  /* Message to be encrypted */
  unsigned char *plaintext =
    (unsigned char *)"The quick brown fox jumps over the lazy dog";

  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, dependant on the
   * algorithm and mode
   */
  unsigned char ciphertext[128];

  /* Buffer for the decrypted text */
  unsigned char decryptedtext[128];

  int decryptedtext_len, ciphertext_len;

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  /* Encrypt the plaintext */
  ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), ekey, iv,
                            ciphertext);

  /* Do something useful with the ciphertext here */
  printf("Ciphertext is:\n");
  BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

  /* Decrypt the ciphertext */
  decryptedtext_len = decrypt(ciphertext, ciphertext_len, dkey, iv,
			      decryptedtext);

  /* Add a NULL terminator. We are expecting printable text */
  decryptedtext[decryptedtext_len] = '\0';

  /* Show the decrypted text */
  printf("Decrypted text is:\n");
  printf("%s\n", decryptedtext);

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  return 0;
}



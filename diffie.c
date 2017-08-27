
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

int check_dh(DH *dh_, char* title_)
{
  int err_code=-1;

  if (dh_) {
    if (DH_check(dh_, &err_code)==0) {
      printf("ERROR(%s, %s): test failed\n", __FUNCTION__, title_ ? title_:"[]");
    }
  }
  return err_code;
}



int main(int argc, char *argv[])
{
  srand(time(NULL));
  DH *dh1;
  DH *dh2;
  unsigned char *shared_secret1;
  unsigned char *shared_secret2;
  char * dh_pub1_str = NULL;
  char * dh_pub2_str = NULL;
  BIGNUM * dh_pub1 = NULL;
  BIGNUM * dh_pub2 = NULL;

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"01234567890123456";
  unsigned int ivlen = 16;

  printf("\n\nInit local DH\n============ \n\n");
  dh1 = DH_new();

  if (1 != DH_generate_parameters_ex(dh1, 512, DH_GENERATOR_2, NULL)) {
    printf("ERROR(%s, %d): \n", __FUNCTION__, __LINE__);
  }

  if (dh1)
    DHparams_print_fp(stdout, dh1);


  //dh2 = DH_generate_parameters(256, 2, NULL, NULL);
  {
    unsigned char *dh_params_str = NULL;
    unsigned char **dh_params_str_ptr = &dh_params_str;
    unsigned int len = 0;

    printf("\n\nInit PKCS #3 for peer DH(PKCS #3, ASN.1)\n=============\n\n");
    len=i2d_DHparams(dh1, dh_params_str_ptr);

    if (dh_params_str_ptr && *dh_params_str_ptr) {
      hexprint(*dh_params_str_ptr, len);
    }

    printf("\n\nInit peer DH with the PKCS #3\n=============\n\n");
    dh2 = d2i_DHparams(NULL, (const unsigned char **)dh_params_str_ptr, len);

    if (dh2)
      DHparams_print_fp(stdout, dh2);

    if (!dh2 || !dh1)
      exit(-1);

  }

  if (check_dh(dh2, "dh2") < 0 )
    return -1;

  if (check_dh(dh1, "dh1") < 0 )
    return -1;


  //  memcpy(dh2, dh1, sizeof(*dh1));

  DH_generate_key(dh1);
  DH_generate_key(dh2);


  if (dh1->pub_key)
    dh_pub1_str = BN_bn2hex(dh1->pub_key);
  if (dh2->pub_key)
    dh_pub2_str = BN_bn2hex(dh2->pub_key);
 
  printf("\n\nGenerate shared-secret locally and on peer\n=============\n\n");

  printf("Extracted public keys would be send to peer: \n");
  printf("1: %s\n", dh_pub1_str ? dh_pub1_str:"[]");
  printf("2: %s\n", dh_pub2_str ? dh_pub2_str:"[]");

  BN_hex2bn(&dh_pub1, dh_pub1_str);
  BN_hex2bn(&dh_pub2, dh_pub2_str);


  shared_secret1 = malloc(DH_size(dh1));
  memset(shared_secret1, 0, DH_size(dh1));
  shared_secret2 = malloc(DH_size(dh2));
  memset(shared_secret2, 0, DH_size(dh2));

  DH_compute_key(shared_secret1, dh_pub2, dh1);
  DH_compute_key(shared_secret2, dh_pub1, dh2);

  // OPENSSL_free(dh_pub1);
  // OPENSSL_free(dh_pub2);

  printf("Public keys in DH structure: ");
  printf("\n1: ");
  BN_print_fp(stdout, dh1->pub_key);
  printf("\n2: ");
  BN_print_fp(stdout, dh2->pub_key);

  printf("\nPriv keys in DH structure: ");
  printf("\n1: ");
  BN_print_fp(stdout, dh1->priv_key);
  printf("\n2: ");
  BN_print_fp(stdout, dh2->priv_key);

  printf("\nShared key: ");
  printf("\n1: ");
  hexprint(shared_secret1, DH_size(dh1));
  printf("2: ");
  hexprint(shared_secret2, DH_size(dh2));


  crypt(shared_secret1, DH_size(dh1), shared_secret2, DH_size(dh2), iv, ivlen);

  free(shared_secret1);
  free(shared_secret2);
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



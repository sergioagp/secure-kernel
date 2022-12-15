/*
 * security_kernel.c
 */

#include "security_kernel.h"
#include "cryptolibs/tiny_sha3/sha3.h"
#include "cryptolibs/ed25519/src/ed25519.h"
#include <string.h>
#include <stdio.h>
#include "xil_printf.h"

/********************* Global Variable Definitions **********************/
unsigned char attest_privkey[ATTEST_KEY_SIZE];
unsigned char attest_pubkey[ATTEST_KEY_SIZE];

unsigned char session_key[32];

/********************* Fuction Definitions **********************/
void create_attest_keypair()
{
	/* create a random seed, and a keypair out of that seed */
	unsigned char keygen_seed[32];
    ed25519_create_seed(keygen_seed);
    ed25519_create_keypair(attest_pubkey, attest_privkey, keygen_seed);

	#ifndef PRINT_DBG
    xil_printf("Seed: ");
    	for (int i = 0; i < 32; i++){
    		xil_printf("%02x", keygen_seed[i]);
    	}
    	xil_printf("Attest Public Key: ");
    	for (int i = 0; i < ATTEST_KEY_SIZE; i++){
    		xil_printf("%02x", attest_pubkey[i]);
    	}
    	xil_printf("Attest Private Key: ");
    	for (int i = 0; i < ATTEST_KEY_SIZE; i++){
    		xil_printf("%02x", attest_privkey[i]);
    	}
	#endif
}

void generate_kernel_certificate(unsigned char* kernel_cert_hash, unsigned char* kernel_hash)
{
    //Generate a certificate over the public attestation key and kernel hash
	sha3_ctx_t hash;

	sha3_init(&hash, 48);
	sha3_update(&hash, kernel_hash, 48);
	sha3_update(&hash, attest_pubkey, 32);
	sha3_final(kernel_cert_hash, &hash);

	#ifndef PRINT_DBG
	xil_printf("\n\rkernel certificate: ");
    	for (int i = 0; i < KERNEL_CERT_SIZE; i++){
    		xil_printf("%02x", kernel_cert_hash[i]);
    	}
	#endif
}

/**
 * Given an attestation public key and secret key, a kernel certificate + sig, generate an attestation and
 * store it in shared memory
 */
void generate_attestation(attestation_t *attestation, unsigned char* kernel_cert, unsigned char* kernel_cert_sig, unsigned char* nonce, unsigned char* verifier_pubkey)
{

	attestation_t	tmp_attestation;
	memcpy((unsigned char *)tmp_attestation.nonce, (unsigned char *)nonce, NONCE_SIZE);
	memcpy((unsigned char *)tmp_attestation.attest_pubkey, (unsigned char *)attest_pubkey, ATTEST_KEY_SIZE);
	memcpy((unsigned char *)tmp_attestation.kernel_cert, (unsigned char *)kernel_cert, KERNEL_CERT_SIZE);
	memcpy((unsigned char *)tmp_attestation.kernel_cert_sig, (unsigned char *)kernel_cert_sig, KERNEL_CERT_SIG_SIZE);

	//Sign the attestation with the attestation secret key
	unsigned char tmp_sig[64];

	ed25519_sign(tmp_sig, (unsigned char *) &tmp_attestation, (ATTESTATION_SIZE - ATTEST_SIG_SIZE), attest_pubkey, attest_privkey);


	ed25519_verify(tmp_sig, (unsigned char *) &tmp_attestation, (ATTESTATION_SIZE - ATTEST_SIG_SIZE), attest_pubkey);
	
	//Write the signature to memory
	memcpy((unsigned char *)tmp_attestation.attest_sig, (unsigned char *)tmp_sig, ATTEST_SIG_SIZE);

	//Generate the shared secret with the verifier.
	unsigned char shared_secret[32];
	unsigned char session_key[32];

	ed25519_key_exchange(shared_secret, verifier_pubkey, attest_privkey);

	sha3(shared_secret, 32, session_key, 32);


	//Sign the shared secret with the attestation key.

	unsigned char shared_secret_sig[32];
	ed25519_sign(shared_secret_sig, shared_secret, 32, attest_pubkey, attest_privkey);

	memcpy((unsigned char *)attestation, (unsigned char *)&tmp_attestation, ATTESTATION_SIZE);

	return;
}

void securitykernel_decrypt(unsigned char *bitstream_key_buffer, unsigned char *ciphertext_addr)
{
	// //Initialize AES driver with the nonce in shared memory and the session key
	// XSecure_AesInitialize(&secure_aes, &csu_dma, XSECURE_CSU_AES_KEY_SRC_KUP, (u32 *) iv_addr, (u32 *) session_key);

	// //Set the destination of decryption to be the bitstream key buffer.
	// XSecure_AesDecryptInit(&secure_aes, bitstream_key_buffer, 32, gcm_tag_addr);

	// //Perform the decryption
	// status = XSecure_AesDecryptUpdate(&secure_aes, ciphertext_addr, 32);
}

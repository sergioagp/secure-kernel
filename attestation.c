/*
 * attestation.c
 */

#include "attestation.h"

#include <stdio.h>
#include <string.h>

#include "crypto.h"

unsigned char attest_privkey[PRIV_KEY_SIZE];
unsigned char attest_pubkey[PUB_KEY_SIZE];

int create_attest_keypair() {
  // Use a cryptographic library to generate an attestation keypair
  // and store the private key in a secure location
  unsigned char keygen_seed[32];
  ed25519_create_seed(keygen_seed);
  ed25519_create_keypair(attest_pubkey, attest_privkey, keygen_seed);
  return 0;
}

int generate_kernel_certificate(unsigned char* kernel_cert_hash, unsigned char* kernel_hash) {
  //Generate a certificate over the public attestation key and kernel hash
	sha3_ctx_t hash;

	sha3_init(&hash, 48);
	sha3_update(&hash, kernel_hash, 48);
	sha3_update(&hash, attest_pubkey, 32);
	sha3_final(kernel_cert_hash, &hash);
}

int generate_attestation(unsigned char* nonce, unsigned char* kernel_hash,
                         unsigned char* kernel_cert_sig, attestation_t* attestation) {
  if (!nonce || !kernel_hash || !kernel_cert_sig || !report) {
    return -1;
  }

  memcpy(attestation->nonce, nonce, NONCE_SIZE);
  memcpy(attestation->attest_pubkey, attest_pubkey, PUB_KEY_SIZE);
  memcpy(attestation->kernel_hash, kernel_hash, KERNEL_HASH_SIZE);
  memcpy(attestation->kernel_cert_sig, kernel_cert_sig, KERNEL_CERT_SIG_SIZE);

  return 0;
}

int sign_attestation(attestation_t* report, unsigned char* attestation_sig) {
  if (!report || !attestation_sig) {
    return -1;
  }

  // Use the attestation private key and a cryptographic library to sign the
  // report and store the signature in attestation_sig
  ed25519_sign(attestation_sig, (unsigned char *) &report, ATTESTATION_SIZE,
               attest_pubkey, attest_privkey);

	if(!ed25519_verify(attestation_sig, (unsigned char *) &report, ATTESTATION_SIZE,
                     attest_pubkey)) {
    return -1;
  }
	
  return 0;
}

int generate_sessionkey(unsigned char* verifier_pubkey, unsigned char* shared_secret_sig, unsigned char* session_key) {
  if (!verifier_pubkey || !session_key) {
    return -1;
  }

  // Use the attestation private key and a cryptographic library to generate a
  // session key based on the verifier's public key and store it in session_key
  unsigned char shared_secret[SHARED_SECR_SIZE];

  ed25519_key_exchange(shared_secret, verifier_pubkey, attest_privkey);

  ed25519_sign(shared_secret_sig, shared_secret, SHARED_SECR_SIZE, attest_pubkey, attest_privkey);

	if(!ed25519_verify(shared_secret_sig, (unsigned char *) shared_secret, SHARED_SECR_SIZE, attest_pubkey)) {
    return -1;
  }

  sha3(shared_secret, SHARED_SECR_SIZE, session_key, SESSION_KEY_SIZE);

  return 0;
}
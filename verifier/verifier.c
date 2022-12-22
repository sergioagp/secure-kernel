#include "verifier.h"

#include <string.h>
#include <stdint.h>

#include "../crypto.h"

unsigned char verifier_pubkey[32];
unsigned char verifier_privkey[32];
unsigned char session_key[32];

/************************** Data definitions ******************/


#define ATTESTATION_SIZE    	(sizeof(attestation_t))

#define NONCE_SIZE            32
#define PRIV_KEY_SIZE		  	  32
#define PUB_KEY_SIZE		  	  32
#define ATTEST_SIG_SIZE       32

#define KERNEL_HASH_SIZE      64
#define KERNEL_CERT_SIZE      32
#define KERNEL_CERT_SIG_SIZE 	32
#define SHARED_SECR_SIZE      32
#define SESSION_KEY_SIZE 	    32

/************************** Data structures ******************/
typedef struct {
	unsigned char nonce[NONCE_SIZE];
	unsigned char attest_pubkey[PUB_KEY_SIZE];
	unsigned char kernel_hash[KERNEL_HASH_SIZE];
	unsigned char kernel_cert_sig[KERNEL_CERT_SIG_SIZE];
} attestation_t;

typedef struct {
	attestation_t attestation;
    unsigned char attest_sig[ATTEST_SIG_SIZE];
    unsigned char shared_secret_sig[SHARED_SECR_SIZE];
} report_t;


int send_attestation_request(unsigned char * nonce, unsigned char * verifier_pubkey) {
  //FIXME: Do not use nonce  as the key seed
  // Generate a random nonce
  ed25519_create_seed(nonce);
  // Generate a public/private keypair for the verifier
  ed25519_create_keypair(verifier_pubkey, verifier_privkey, nonce);
  return 0;
}

int verify_kernel_certificate(const unsigned char* certificate, const unsigned char* certificate_sig) {
  unsigned char sig_decrypted_hash[KERNEL_HASH_SIZE];
	(void) certificate;
	(void) certificate_sig;
	(void) sig_decrypted_hash;
  //TODO: Decrypt the signature with the root public key

  //TODO: The hash is contained in the last 48 bytes of the signature

  //FIXME: Change for string compare
  // if(sig_decrypted_hash == certificate) {
  //     return -1;
  // }

  return 0;
}

int generate_key_exchange(const unsigned char *attest_pubkey, const unsigned char *shared_secret_sig, unsigned char *session_key) {
  unsigned char shared_secret[32];
  ed25519_key_exchange(shared_secret, attest_pubkey, verifier_privkey);

  // Verify if the shared secret is properly signed
  if(!ed25519_verify(shared_secret_sig,(unsigned char *) shared_secret, SHARED_SECR_SIZE, attest_pubkey)) {
      return -1;
  }

  // Hash the shared secret to obtain the shared AES key.
  sha3(shared_secret, 32, session_key, 32);

  return 0;

}

int recv_report_from_sk(const unsigned char *report, const unsigned int report_len) {
  if (report_len != sizeof(report_t)) {
    // handle error, array is not the expected size
    return -1;
  }

  report_t *report_parsed = (report_t *) report;


  // Hash the kernel hash + attestation PK together
  unsigned char kernel_cert_hash[KERNEL_HASH_SIZE];
  sha3_ctx_t hash;
  sha3_init(&hash, 48);
  sha3_update(&hash, report_parsed->attestation.kernel_hash, 48);
  sha3_update(&hash, report_parsed->attestation.attest_pubkey, 32);
  sha3_final(kernel_cert_hash, &hash);


  //1. Verify the security kernel hash from a list of trusted hashes
  if(!verify_kernel_certificate(kernel_cert_hash, report_parsed->attestation.kernel_cert_sig)) {
      //security kernel not trusted 
      return -1;
  }
  
  //Trust in the security kernel and the attestation public key

  // 2. Verify that the attestation report is signed with the secret attestation key
  if(!ed25519_verify(report_parsed->attest_sig,(unsigned char *) &report_parsed->attestation,
                     sizeof(attestation_t), report_parsed->attestation.attest_pubkey)) {
        return -1;
  }

  //Trust in the attestation report

  // 3. Generate shared secret and AES key (session_key)
  if(!generate_key_exchange(report_parsed->attestation.attest_pubkey, report_parsed->shared_secret_sig, session_key)) {
          return -1;
  }

  return 0;
}


// Encrypt the bitstream key with the session key, and send the encrypted bitstream key
// to the FPGA
// session_key: bytes object with length 32 containing session key with FPGA
// bitstream_key: bytes object with length 32 containing key used to encrypt the bitstream
// ser: serial object
// int send_bitstream_key(unsigned char *session_key, unsigned char *bitstream_key) {
//     cipher = AES.new(session_key, AES.MODE_GCM, nonce=rand_nonce)
//     ciphertext, tag = cipher.encrypt_and_digest(bitstream_key)


//     //send ciphertext
//     return
// }

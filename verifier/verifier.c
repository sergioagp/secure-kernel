#include <stdint.h>
#include <string.h>
#include "verifier.h"
#include "cryptolibs/tiny_sha3/sha3.h"
#include "cryptolibs/ed25519/ed25519.h"

unsigned char verifier_pk[32];
unsigned char verifier_sk[32];

/************************** Data definitions ******************/


#define ATTESTATION_SIZE    	(sizeof(attestation_t))

#define NONCE_SIZE				0x20
#define ATTEST_KEY_SIZE		  	0x20
#define ATTEST_SIG_SIZE     	0x40
#define KERNEL_HASH_SIZE 		0x30
#define KERNEL_CERT_SIG_SIZE 	0x200
#define SESSION_KEY_SIZE		0x20

/************************** Data structures ******************/
typedef struct{
	unsigned char nonce[NONCE_SIZE];
	unsigned char attest_pubkey[ATTEST_KEY_SIZE];
	unsigned char kernel_hash[KERNEL_HASH_SIZE];
	unsigned char kernel_cert_sig[KERNEL_CERT_SIG_SIZE];
} attestation_t;

typedef struct{
	attestation_t attestation;
    unsigned char attest_sig[ATTEST_SIG_SIZE];
    unsigned char shared_secret_sig[SHARED_SECRET_SIG_SIZE];
} report_t;


int send_attestation_request(unsigned char * nonce, unsigned char * verifier_pubkey)
{
    // Generate a random nonce
    ed25519_create_seed(nonce);

    // Generate a public/private keypair for the verifier
    ed25519_create_keypair(verifier_pk, verifier_sk, nonce);
    return 0;
}

int parse_attestation(report_t* parsed_report, const unsigned char* report, uint32_t report_len)
{
    if (report_len != sizeof(report_t)) {
        // handle error, array is not the expected size
        return -1
    }

    memcpy(parsed_report->attestation.nonce, report, NONCE_SIZE);
    memcpy(parsed_report->attestation.attest_pubkey, report + NONCE_SIZE, ATTEST_KEY_SIZE);
    memcpy(parsed_report->attestation.kernel_hash, report + NONCE_SIZE + ATTEST_KEY_SIZE, KERNEL_HASH_SIZE);
    memcpy(parsed_report->attestation.kernel_cert_sig, report + NONCE_SIZE + ATTEST_KEY_SIZE + KERNEL_HASH_SIZE, KERNEL_CERT_SIG_SIZE);
    memcpy(parsed_report->attest_sig, report + NONCE_SIZE + ATTEST_KEY_SIZE + KERNEL_HASH_SIZE + KERNEL_CERT_SIG_SIZE, ATTEST_SIG_SIZE);
}

/**
 * Verifies the given kernel certificate using the provided signature.
 * @brief Given SHA3-384(kernel_hash || attest_pk) and a 512-byte RSA PKCS#1.5
 * signature of the hash, return true if the signature is verified against
 * the trusted public root key.
 * @param certificate Pointer to the kernel certificate to be verified.
 * @param certificate_sig Pointer to the signature for the kernel certificate.
 * @return 0 if the certificate is verified, non-zero if the verification fails.
 */
int verify_kernel_certificate(const unsigned char* certificate, const unsigned char* certificate_sig)
{
    unsigned char sig_decrypted_hash[KERNEL_HASH_SIZE];

    //TODO: Decrypt the signature with the root public key

    //TODO: The hash is contained in the last 48 bytes of the signature

    //FIXME: Change for string compare
    if(sig_decrypted_hash == certificate) {
        return -1;
    }

    return 0;

}

/**
 * Given the attestation report, return True if the attestation
 * report is signed by the secret attestation key corresponding
 * to the public attestation key in the report.
 * @param certificate Pointer to the kernel certificate to be verified.
 * @param certificate_sig Pointer to the signature for the kernel certificate.
 * @return 0 if the certificate is verified, non-zero if the verification fails.
 */
int verify_attestation_signature(const attestation_t* attestation, const unsigned char* attestation_sig)
{
    unsigned char sig_decrypted_hash[KERNEL_HASH_SIZE];

    if(!ed25519_verify(attestation_sig,(const unsigned char *) attestation, sizeof(attestation_t), attestation->attest_pubkey)) {
        return -1;
    }

    return 0;

}

int verify_attestation_report(const unsigned char * report, uint32_t report_len, attestation_t* attestation)
{
  report_t parsed_report;
  parse_attestation(&parsed_report, report, report_len);
  
  // Hash the kernel hash + attestation PK together
  unsigned char kernel_cert_hash[KERNEL_HASH_SIZE];
  sha3_ctx_t hash;
  sha3_init(&hash, 48);
  sha3_update(&hash, parsed_report.attestation.kernel_hash, 48);
  sha3_update(&hash, parsed_report.attestation.attest_pubkey, 32);
  sha3_final(kernel_cert_hash, &hash);

  //Verify the security kernel hash from a list of trusted hashes
  if(!verify_kernel_certificate(kernel_cert_hash, parsed_report.attestation.kernel_cert_sig)) {
      //security kernel not trusted 
      return -1;
  }
  
  // At this stage, trust is established in the security kernel and the attestation public key

  // Verify that the attestation report is signed with the secret attestation key
  if(!verify_attestation_signature(&parsed_report.attestation, parsed_report.attest_sig)) {
      //security kernel not trusted 
      return -1;
  }

  return 0; // Return 0 on success, non-zero on failure
}
/* @param[in] nonce Nonce used in the attestation process.
 * @param[in] kernel_pubkey Public key of the security kernel.
 * @param[out] session_key Shared session key generated during the attestation process.
*/
int generate_key_exchange(const attestation_t* attestation, unsigned char *shared_secret_sig, unsigned char * session_key)
{
  unsigned char shared_secret[32];
  ed25519_key_exchange(shared_secret, attestation->attest_pubkey, verifier_sk);

  // Verify if the shared secret is properly signed
  if(!ed25519_verify(shared_secret_sig,(const unsigned char *) shared_secret, SHARED_SECRET_SIZE, attestation->attest_pubkey)) {
      return -1;
  }

  // Hash the shared secret to obtain the shared AES key.
  sha3(shared_secret, 32, session_key, 32);

  return 0;

}

// Encrypt the bitstream key with the session key, and send the encrypted bitstream key
// to the FPGA
// session_key: bytes object with length 32 containing session key with FPGA
// bitstream_key: bytes object with length 32 containing key used to encrypt the bitstream
// ser: serial object
int send_bitstream_key(unsigned char *session_key, unsigned char *bitstream_key):
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=rand_nonce)
    ciphertext, tag = cipher.encrypt_and_digest(bitstream_key)


    //send ciphertext
    return
}
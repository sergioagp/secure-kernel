#include <stdio.h>

#include "platform.h"
#include "xil_printf.h"

#include "security_kernel.h"
#include "firmware.h"
#include "bitstream.h"

typedef struct{
	attestation_t attestation;
    unsigned char attest_sig[ATTEST_SIG_SIZE];
    unsigned char shared_secret_sig[SHARED_SECRET_SIG_SIZE];
} report_t;

unsigned char kernel_hash[32] = {0x0E,0xAB,0x42,0xDE,0x4C,0x3C,0xEB,0x92,0x35,0xFC,0x91,0xAC,0xFF,0xE7,0x46,0xB2,0x9C,
                                0x29,0xA8,0xC3,0x66,0xB7,0xC6,0x0E,0x4E,0x67,0xC4,0x66,0xF3,0x6A,0x43,0x04,0xC0,0x0F,
                                0xA9,0xCA,0xF9,0xD8,0x79,0x76,0xBA,0x46,0x9B,0xCB,0xE0,0x67,0x13,0xB4,0x35,0xF0,0x91,
                                0xEF,0x27,0x69,0xFB,0x16,0x0C,0xDA,0xB3,0x3D,0x36,0x70,0x68,0x0E};


void wait_attestation_request(unsigned char* nonce, unsigned char* verifier_pubkey)
{
  unsigned char keygen_seed[32];
  ed25519_create_seed(keygen_seed);
  ed25519_create_keypair(attest_pubkey, attest_privkey, keygen_seed);
}


// void decrypt_bitstream_key(unsigned char* bitstream_key_buffer){

// 	//Get the pointer to the tag, ciphertext, and IV
// 	// u8* iv_addr = (u8*) (SHARED_MEM_BASE + BITSTREAM_KEY_OFFSET);
// 	// u8* gcm_tag_addr = (u8*) (SHARED_MEM_BASE + BITSTREAM_KEY_OFFSET + IV_SIZE);
// 	// u8* ciphertext_addr = (u8*) (SHARED_MEM_BASE + BITSTREAM_KEY_OFFSET + IV_SIZE + TAG_SIZE);

//     //get ciphertext_addr
//     unsigned char* ciphertext_addr;
//     securitykernel_decrypt(bitstream_key_buffer, ciphertext_addr);
// }

int main() {
  init_platform();
  
  unsigned char nonce[NONCE_SIZE];
  unsigned char verifier_pubkey[PUBKEY_SIZE];
  wait_attestation_request(nonce, verifier_pubkey);
  
  xil_printf("--Security Kernel--\r\n");
  create_attest_keypair();

	unsigned char kernel_cert[KERNEL_CERT_SIZE];
  generate_kernel_certificate(kernel_cert, kernel_hash);
  
  unsigned char kernel_cert_sig[KERNEL_CERT_SIG_SIZE];
  fw_signature(kernel_cert_sig, kernel_cert);
  
  attestation_t attestation;
  generate_attestation(nonce, kernel_hash, kernel_cert_sig, &attestation);

  unsigned char attestation_sig[ATTEST_SIG_SIZE];
  sign_attestation(&attestation, attestation_sig);

  unsigned char shared_secret_sig[SHARED_SECR_SIG_SIZE];
  unsigned char session_key[SESSION_KEY_SIZE];
  generate_sessionkey(verifier_pubkey, shared_secret_sig, session_key)

  send_report_to_verifier();

   //Now, wait for the runtime to provide an encrypted bitstream (encrypted with bitstream decryption key).
//    unsigned int bitstream_size = wait_for_bitstream_load();

//    //Decrypt the bitstream decryption key.
//    unsigned char bitstream_key[32] = {0};
//    decrypt_bitstream_key(bitstream_key);

//    //Decrypt the bitstream and load it into the FPGA.
//    program_bitstream(bitstream_key);

  while(1);
  cleanup_platform();
  return 0;
}




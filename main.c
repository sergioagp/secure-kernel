#include <stdio.h>

#include "platform.h"
#include "xil_printf.h"

#include "firmware.h"
#include "attestation.h"
#include "security_kernel.h"

typedef struct{
	attestation_t attestation;
    unsigned char attest_sig[ATTEST_SIG_SIZE];
    unsigned char shared_secret_sig[SHARED_SECR_SIZE];
} report_t;

unsigned char kernel_hash[KERNEL_HASH_SIZE] = {0x0E,0xAB,0x42,0xDE,0x4C,0x3C,0xEB,0x92,0x35,0xFC,
                                 0x91,0xAC,0xFF,0xE7,0x46,0xB2,0x9C,0x29,0xA8,0xC3,
                                 0x66,0xB7,0xC6,0x0E,0x4E,0x67,0xC4,0x66,0xF3,0x6A,
                                 0x43,0x04,0xC0,0x0F,0xA9,0xCA,0xF9,0xD8,0x79,0x76,
                                 0xBA,0x46,0x9B,0xCB,0xE0,0x67,0x13,0xB4,0x35,0xF0,
                                 0x91,0xEF,0x27,0x69,0xFB,0x16,0x0C,0xDA,0xB3,0x3D,
                                 0x36,0x70,0x68,0x0E};

void print_array(unsigned char* array, unsigned int len) {
  for (int i = 0; i < len; i++){
    		xil_printf("%02x", array[i]);
  }
}

void wait_attestation_request(unsigned char* nonce, unsigned char* verifier_pubkey) {
  unsigned char keygen_seed[32];
  unsigned char verifier_privkey[32];
  ed25519_create_seed(keygen_seed);
  ed25519_create_keypair(verifier_pubkey, verifier_privkey, keygen_seed);
}

void send_report_to_verifier(report_t* report) {
  xil_printf("Report Generated!\r\n");
  xil_printf("\r\nNONCE: ");
  print_array(report->attestation.nonce, NONCE_SIZE);
  xil_printf("\r\nATTEST PUBKEY: ");
  print_array(report->attestation.attest_pubkey, PUB_KEY_SIZE);
  xil_printf("\r\nKERNEL HASH: ");
  print_array(report->attestation.kernel_hash, KERNEL_HASH_SIZE);
  xil_printf("\r\nKERNEL CERT SIG: ");
  print_array(report->attestation.kernel_cert_sig, KERNEL_CERT_SIG_SIZE);
  xil_printf("\r\n ATTEST SIG: ");
  print_array(report->attest_sig, ATTEST_SIG_SIZE);
  xil_printf("\r\nShared Secrect SIG: ");
  print_array(report->shared_secret_sig, SHARED_SECR_SIZE);
  
  xil_printf("\r\nSending report to the verifier...");
  
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
  // Initialize the platform for use
  init_platform();

  // Wait for an attestation request and store the nonce and verifier public key
  unsigned char nonce[NONCE_SIZE];
  unsigned char verifier_pubkey[PUB_KEY_SIZE];
  wait_attestation_request(nonce, verifier_pubkey);
  
  xil_printf("-- Security Kernel --\r\n");

  // Wait for an attestation request and store the nonce and verifier public key
  create_attest_keypair();

  // Generate the kernel certificate using the kernel hash and store it in kernel_cert
	unsigned char kernel_cert[KERNEL_CERT_SIZE];
  generate_kernel_certificate(kernel_cert, kernel_hash);
  
  // Generate a signature for the kernel certificate and store it in kernel_cert_sig
  unsigned char kernel_cert_sig[KERNEL_CERT_SIG_SIZE];
  fw_signature(kernel_cert_sig, kernel_cert);
  
  // Generate the attestation using the nonce, kernel hash, and kernel certificate 
  attestation_t attestation;
  generate_attestation(nonce, kernel_hash, kernel_cert_sig, &attestation);

  // Sign the attestation and store the signature in attestation_sig
  unsigned char attestation_sig[ATTEST_SIG_SIZE];
  sign_attestation(&attestation, attestation_sig);

  // Generate the session key using the verifier public key and store it in session_key
  // Also generate the shared secret signature and store it in shared_secret_sig
  unsigned char shared_secret_sig[SHARED_SECR_SIZE];
  unsigned char session_key[SESSION_KEY_SIZE];
  generate_sessionkey(verifier_pubkey, shared_secret_sig, session_key);

  // Send the report to the verifier
  report_t  report;
  memcpy((unsigned char *)&report.attestation, (unsigned char *) &attestation, ATTESTATION_SIZE);
  memcpy(report.attest_sig, attestation_sig, ATTEST_SIG_SIZE);
  memcpy(report.shared_secret_sig, shared_secret_sig, SHARED_SECR_SIZE);
  send_report_to_verifier(&report);

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




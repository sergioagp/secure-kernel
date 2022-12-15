
/*
 * main.c: main operation of security kernel application
 */


#include <stdio.h>
#include "platform.h"
#include "xil_printf.h"
#include "firmware.h"
#include "security_kernel.h"
#include "bitstream.h"

unsigned char kernel_hash[32];

void wait_attestation_request(unsigned char* nonce, unsigned char* verifier_pubkey)
{
	(void) nonce;
	(void) verifier_pubkey;
}

void send_attestation_report(attestation_t* attestation)
{

}

void request_kernel_signature(unsigned char* kernel_cert_sig, unsigned char* kernel_cert)
{
    sign_kernelcertificate(kernel_cert_sig, kernel_cert);

    #ifdef PRINT_DBG
    xil_printf("\n\rkernel certificate signature: ");
    	for (i = 0; i < KERNEL_CERT_SIG_SIZE; i++){
    		xil_printf("%02x", kernel_cert_sig[i]);
    	}
	#endif
}

void decrypt_bitstream_key(unsigned char* bitstream_key_buffer){

	//Get the pointer to the tag, ciphertext, and IV
	// u8* iv_addr = (u8*) (SHARED_MEM_BASE + BITSTREAM_KEY_OFFSET);
	// u8* gcm_tag_addr = (u8*) (SHARED_MEM_BASE + BITSTREAM_KEY_OFFSET + IV_SIZE);
	// u8* ciphertext_addr = (u8*) (SHARED_MEM_BASE + BITSTREAM_KEY_OFFSET + IV_SIZE + TAG_SIZE);

    //get ciphertext_addr
    unsigned char* ciphertext_addr;
    securitykernel_decrypt(bitstream_key_buffer, ciphertext_addr);
}

int main()
{
    init_platform();
    unsigned char nonce[NONCE_SIZE];
    unsigned char verifier_pubkey[ATTEST_KEY_SIZE];

    attestation_t attestation;

	unsigned char kernel_cert_hash[48];
    unsigned char kernel_cert_sig[512];
    unsigned char session_key[SESSION_KEY_SIZE];


    xil_printf("=====================Security Kernel=================");

    //Block until runtime is ready, and generate an attestation for the runtime.
    wait_attestation_request(nonce, verifier_pubkey);

    create_attest_keypair();


//    generate_kernel_certificate(kernel_cert_hash, kernel_hash);
//    request_kernel_signature(kernel_cert_sig, kernel_cert_hash);
//
//    //Once the precedure finishes, a shared key will be placed in session_key
//    generate_attestation(&attestation, kernel_cert_hash, kernel_cert_sig, nonce, verifier_pubkey);
//    send_attestation_report(&attestation);
//
//    //Now, wait for the runtime to provide an encrypted bitstream (encrypted with bitstream decryption key).
//    unsigned int bitstream_size = wait_for_bitstream_load();
//
//    //Decrypt the bitstream decryption key.
//    unsigned char bitstream_key[32] = {0};
//    decrypt_bitstream_key(bitstream_key);
//
//    //Decrypt the bitstream and load it into the FPGA.
//    program_bitstream(bitstream_key);

    while(1);
    cleanup_platform();
    return 0;
}




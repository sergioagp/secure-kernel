/*
 * security_kernel.h
 */

#ifndef SRC_SECURITY_KERNEL_H_
#define SRC_SECURITY_KERNEL_H_


/****************************** Include Files *******************/

/************************** Data definitions ******************/


#define ATTESTATION_SIZE    	(sizeof(attestation_t))

#define NONCE_SIZE				0x20
#define ATTEST_KEY_SIZE		  	0x20
#define ATTEST_SIG_SIZE     	0x40
#define KERNEL_CERT_SIZE 		0x30
#define KERNEL_CERT_SIG_SIZE 	0x200
#define SESSION_KEY_SIZE		0x20
/************************** Data structures ******************/
typedef struct{
	unsigned char nonce[NONCE_SIZE];
	unsigned char attest_pubkey[ATTEST_KEY_SIZE];
	unsigned char kernel_cert[ATTEST_SIG_SIZE];
	unsigned char kernel_cert_sig[KERNEL_CERT_SIZE];
	unsigned char attest_sig[KERNEL_CERT_SIG_SIZE];
} attestation_t;

/**************************Function prototypes ******************/
void create_attest_keypair();
void generate_kernel_certificate(unsigned char* kernel_cert_hash, unsigned char* kernel_hash);
void generate_attestation(attestation_t *attestation, unsigned char* kernel_cert_hash, unsigned char* kernel_cert_sig, unsigned char* nonce, unsigned char* verifier_pubkey);
void securitykernel_decrypt(unsigned char *bitstream_key_buffer, unsigned char *ciphertext_addr);
// u32 decrypt_bitstream_key(u8* bitstream_key_buffer, u8* session_key);

// u32 wait_for_bitstream_load();

// void program_bitstream(u8* bitstream_key, u8* addr, u32 size);



#endif /* SRC_SECURITY_KERNEL_H_ */

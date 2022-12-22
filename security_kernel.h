/*
 * security_kernel.h
 */

#ifndef SRC_SECURITY_KERNEL_H_
#define SRC_SECURITY_KERNEL_H_

/**************************Function prototypes ******************/
void securitykernel_decrypt(unsigned char *session_key, unsigned char *ciphertext,
                             unsigned int  ciphertext_len, unsigned char *plaintext);
void securitykernel_encrypt(unsigned char *session_key, unsigned char *plaintext,
                             unsigned int  ciphertext_len, unsigned char *ciphertext);
#endif /* SRC_SECURITY_KERNEL_H_ */

/*
 * attestation.h
 */

#ifndef ATTESTATION_H_
#define ATTESTATION_H_

#include <stddef.h>
#include <stdint.h>

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

typedef struct{
	unsigned char nonce[NONCE_SIZE];
	unsigned char attest_pubkey[PUB_KEY_SIZE];
	unsigned char kernel_hash[KERNEL_HASH_SIZE];
	unsigned char kernel_cert_sig[KERNEL_CERT_SIG_SIZE];
} attestation_t;

/**
 * @brief Generates an attestation keypair and stores the private key in a secure location.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int create_attest_keypair();

/**
 * @brief Generates a certificate from the kernel hash .
 * @param[in] kernel_hash The hash of the kernel to include in the report.
 * @param[out] kernel_cert_sig The signature of the kernel certificate to include in the report.
 * @return 0 on success, or a negative error code on failure.
 */
int generate_kernel_certificate(unsigned char* kernel_hash, unsigned char* kernel_cert_hash);

/**
 * @brief Generates an attestation report based on the given nonce, kernel hash, and kernel
 * certificate signature.
 *
 * @param[in] nonce The nonce to include in the report.
 * @param[in] kernel_hash The hash of the kernel to include in the report.
 * @param[in] kernel_cert_sig The signature of the kernel certificate to include in the report.
 * @param[out] report The attestation report.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int generate_attestation(unsigned char* nonce, unsigned char* kernel_hash,
                         unsigned char* kernel_cert_sig, attestation_t* report);

/**
 * @brief Signs an attestation report using the attestation private key.
 *
 * @param[in] report The attestation report to be signed.
 * @param[out] attestation_sig The signature of the report.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int sign_attestation(attestation_t* report, unsigned char* attestation_sig);

/**
 * @brief Generates a session key based on the verifier's public key and the attestation private key.
 *
 * @param[in] verifier_pubkey The verifier's public key.
 * @param[out] shared_secret_sig The generated signed shared secret key.
 * @param[out] session_key The generated session key.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int generate_sessionkey(unsigned char* verifier_pubkey, unsigned char* shared_secret_sig, unsigned char* session_key);

#endif /* ATTESTATION_H_ */

#ifndef VERIFIER_H
#define VERIFIER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Sends an attestation request to the security kernel.
 *
 * @param[out] nonce Nonce to be used in the attestation process.
 * @param[out] verifier_pubkey Public key of the verifier.
 *
 * @return 0 on success, non-zero on failure.
 */
int send_attestation_request(uint8_t* nonce, uint8_t* verifier_pubkey);

/**
 * @brief Verifies the attestation report provided by the security kernel.
 *
 * @param[in] report Pointer to the attestation report.
 * @param[in] report_len Length of the attestation report in bytes.
 *
 * @return 0 on success, non-zero on failure.
 */
int verify_attestation_report(const unsigned char * report, uint32_t report_len, attestation_t* attestation);

#ifdef __cplusplus
}

#endif

#endif /* VERIFIER_H */
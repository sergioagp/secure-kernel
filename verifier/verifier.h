#ifndef VERIFIER_H
#define VERIFIER_H

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
int send_attestation_request(unsigned char* nonce, unsigned char* verifier_pubkey);

/**
 * @brief Receive the attestation report provided by the security kernel.
 *
 * @param[in] report Pointer to the attestation report.
 * @param[in] report_len Length of the attestation report in bytes.
 *
 * @return 0 on success, non-zero on failure.
 */
int recv_report_from_sk(const unsigned char* report, const unsigned int report_len);


#ifdef __cplusplus
}

#endif

#endif /* VERIFIER_H */

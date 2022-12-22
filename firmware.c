#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "crypto.h"
#include "xil_printf.h"

#define RSA_SIZE 						512 /* 4096 bits */

unsigned char *encrypt_sig_out;

void fw_signature(unsigned char *kernel_certificate_sig, unsigned char *kernel_certificate) {

  //FIXME: Change to RSA instead of using the ed25519

	//Sign the kernel certificate with the root private key.
	unsigned char device_privkey[32];
	unsigned char device_pubkey[32];
	unsigned char keygen_seed[32];
	ed25519_create_seed(keygen_seed);
	ed25519_create_keypair(device_pubkey, device_privkey, keygen_seed);


	ed25519_sign(kernel_certificate_sig, (unsigned char *) &kernel_certificate, RSA_SIZE, device_pubkey, device_privkey);

  //Verify the signature
	if(!ed25519_verify(kernel_certificate_sig, (unsigned char *) &kernel_certificate, RSA_SIZE, device_pubkey)){
		return;
	}
	//Send the signature back to the Security Monitor
	return;
}

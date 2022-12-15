#include "firmware.h"	

void sign_kernelcertificate(unsigned char *kernel_certificate_sig, unsigned char *kernel_certificate)
{    
    // XSecure_RsaInitialize(&secure_rsa, root_mod, NULL, root_sk);
	// if(XST_SUCCESS != XSecure_RsaPrivateDecrypt(&secure_rsa, kernel_cert,
	// 		size, kernel_cert_sig)){
	// 	XPfw_Printf(DEBUG_ERROR, "PMU: Failed to sign Kernel Certificate\r\n");
	// 	return;
	// }

	// XPfw_Printf(DEBUG_DETAILED, "PMU: Generated Kernel Certificate signature\r\n");
}
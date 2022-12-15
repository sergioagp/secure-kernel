#ifndef SRC_SECURITY_KERNEL_H_
#define SRC_SECURITY_KERNEL_H_

void wait_for_bitstream_load(void);
void program_bitstream(unsigned char * bitstream_key);

#endif // SRC_SECURITY_KERNEL_H_
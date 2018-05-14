#ifndef _SHS_LIB_H_
#define _SHS_LIB_H_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct _Sha Sha256;
struct _Sha
{
  unsigned char msg_block[64]; // 512 bit block (8 bit bytes)
  unsigned int block_idx;
  unsigned long long bit_cnt;  // 64 bit
  unsigned int msg_digest[8];  // 256 bit digest (32 bit bytes)
};

Sha256 *sha256_new();
int sha256_load(Sha256 *sha, const unsigned char data[], const unsigned int len);
int sha256_hash(Sha256 *sha);

#endif /* _SHS_LIB_H_ */
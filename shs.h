#ifndef _SHS_LIB_H_
#define _SHS_LIB_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*------------------------------*/
/* SHA-1                        */
/*------------------------------*/
typedef struct _Sha1 Sha1;
struct _Sha1 {
  unsigned char msg_block[64];  // 512 bit block (8 bit bytes)
  unsigned int block_idx;
  unsigned long long bit_cnt;  // 64 bit
  unsigned int msg_digest[5];  // 160 bit digest (32 bit bytes)
};

Sha1 *sha1_new();
int sha1_load(Sha1 *sha, const unsigned char data[],
                const unsigned int len);
int sha1_hash(Sha1 *sha);

/*------------------------------*/
/* SHA-256                      */
/*------------------------------*/
typedef struct _Sha256 Sha256;
struct _Sha256 {
  unsigned char msg_block[64];  // 512 bit block (8 bit bytes)
  unsigned int block_idx;
  unsigned long long bit_cnt;  // 64 bit
  unsigned int msg_digest[8];  // 256 bit digest (32 bit bytes)
};

Sha256 *sha256_new();
int sha256_load(Sha256 *sha, const unsigned char data[],
                const unsigned int len);
int sha256_hash(Sha256 *sha);

/*------------------------------*/
/* SHA-224                      */
/*------------------------------*/
typedef struct _Sha224 Sha224;
struct _Sha224 {
  unsigned char msg_block[64];  // 512 bit block (8 bit bytes)
  unsigned int block_idx;
  unsigned long long bit_cnt;  // 64 bit
  unsigned int msg_digest[8];  // 224 bit digest after truncation (32 bit bytes)
};

Sha224 *sha224_new();
int sha224_load(Sha224 *sha, const unsigned char data[],
                const unsigned int len);
int sha224_hash(Sha224 *sha);

/*------------------------------*/
/* SHA-512                      */
/*------------------------------*/
typedef struct _Sha512 Sha512;
struct _Sha512 {
  unsigned char msg_block[128];  // 1024 bit block (8 bit bytes)
  unsigned long long byte_idx;
  unsigned long long bit_cnt[2];        // 128 bit
  unsigned long long msg_digest[8];  // 512 bit digest (64 bit words)
};

Sha512 *sha512_new();
int sha512_load(Sha512 *sha, const unsigned char data[],
                const unsigned int len);
int sha512_hash(Sha512 *sha);

/*------------------------------*/
/* SHA-384                      */
/*------------------------------*/
typedef struct _Sha384 Sha384;
struct _Sha384 {
  unsigned char msg_block[128];  // 1024 bit block (8 bit bytes)
  unsigned long long byte_idx;
  unsigned long long bit_cnt[2];     // 128 bit
  unsigned long long msg_digest[8];  // 384 bits after truncation (64 bit words)
};

Sha384 *sha384_new();
int sha384_load(Sha384 *sha, const unsigned char data[],
                const unsigned int len);
int sha384_hash(Sha384 *sha);

/*------------------------------*/
/* SHA-512/224                  */
/*------------------------------*/
typedef struct _Sha512_224 Sha512_224;
struct _Sha512_224 {
  unsigned char msg_block[128];  // 1024 bit block (8 bit bytes)
  unsigned long long byte_idx;
  unsigned long long bit_cnt[2];     // 128 bit
  unsigned long long msg_digest[8];  // 224 bits after truncation (64 bit words)
};

Sha512_224 *sha512_224_new();
int sha512_224_load(Sha512_224 *sha, const unsigned char data[],
                const unsigned int len);
int sha512_224_hash(Sha512_224 *sha);

/*------------------------------*/
/* SHA-512/256                  */
/*------------------------------*/
typedef struct _Sha512_256 Sha512_256;
struct _Sha512_256 {
  unsigned char msg_block[128];  // 1024 bit block (8 bit bytes)
  unsigned long long byte_idx;
  unsigned long long bit_cnt[2];     // 128 bit
  unsigned long long msg_digest[8];  // 224 bits after truncation (64 bit words)
};

Sha512_256 *sha512_256_new();
int sha512_256_load(Sha512_256 *sha, const unsigned char data[],
                    const unsigned int len);
int sha512_256_hash(Sha512_256 *sha);

#endif /* _SHS_LIB_H_ */
#include "shs.h"

static uint32_t endian = 0xaabcdeff;

// constants
static uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static uint32_t initials[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                               0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};

#define BLOCK_SIZE 64  // 512 bits

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n) (((x) >> (n)))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define USIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define USIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define LSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define LSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

static uint32_t endian_reverse32(uint32_t n) {
  unsigned char *np = (unsigned char *)&n;
  return ((uint32_t)np[0] << 24) | ((uint32_t)np[1] << 16) |
         ((uint32_t)np[2] << 8) | (uint32_t)np[3];
}

static int compute_block(Sha224 *sha) {
  unsigned int var_a;
  unsigned int var_b;
  unsigned int var_c;
  unsigned int var_d;
  unsigned int var_e;
  unsigned int var_f;
  unsigned int var_g;
  unsigned int var_h;

  unsigned int W[64];
  unsigned int T1;
  unsigned int T2;

  // prepare message schedule
  for (int t = 0; t <= 15; t++) {
    W[t] = (sha->msg_block[t * 4]) << 24;
    W[t] |= (sha->msg_block[t * 4 + 1]) << 16;
    W[t] |= (sha->msg_block[t * 4 + 2]) << 8;
    W[t] |= (sha->msg_block[t * 4 + 3]);
  }

  for (int t = 16; t < BLOCK_SIZE; t++) {
    W[t] = LSIG1(W[t - 2]) + W[t - 7] + LSIG0(W[t - 15]) + W[t - 16];
  }

  // initialize working variables
  var_a = sha->msg_digest[0];
  var_b = sha->msg_digest[1];
  var_c = sha->msg_digest[2];
  var_d = sha->msg_digest[3];
  var_e = sha->msg_digest[4];
  var_f = sha->msg_digest[5];
  var_g = sha->msg_digest[6];
  var_h = sha->msg_digest[7];

  // do the math
  for (int t = 0; t < BLOCK_SIZE; t++) {
    T1 = var_h + USIG1(var_e) + CH(var_e, var_f, var_g) + K[t] + W[t];
    T2 = USIG0(var_a) + MAJ(var_a, var_b, var_c);
    var_h = var_g;
    var_g = var_f;
    var_f = var_e;
    var_e = var_d + T1;
    var_d = var_c;
    var_c = var_b;
    var_b = var_a;
    var_a = T1 + T2;
  }

  // compute intermediate hash value
  sha->msg_digest[0] += var_a;
  sha->msg_digest[1] += var_b;
  sha->msg_digest[2] += var_c;
  sha->msg_digest[3] += var_d;
  sha->msg_digest[4] += var_e;
  sha->msg_digest[5] += var_f;
  sha->msg_digest[6] += var_g;
  sha->msg_digest[7] += var_h;

  sha->block_idx = 0;

  return 1;
}

Sha224 *sha224_new() {
  Sha224 *sha;
  sha = malloc(sizeof(Sha224));
  sha->block_idx = 0;
  sha->bit_cnt = 0;
  sha->msg_digest[0] = initials[0];
  sha->msg_digest[1] = initials[1];
  sha->msg_digest[2] = initials[2];
  sha->msg_digest[3] = initials[3];
  sha->msg_digest[4] = initials[4];
  sha->msg_digest[5] = initials[5];
  sha->msg_digest[6] = initials[6];
  sha->msg_digest[7] = initials[7];
  return sha;
}

int sha224_load(Sha224 *sha, const unsigned char data[],
                const unsigned int len) {
  if (!len) return 0;

  for (unsigned int i = 0; i < len; ++i) {
    sha->msg_block[sha->block_idx++] = data[i];
    sha->bit_cnt += 8;
    if (sha->block_idx == BLOCK_SIZE) {
      compute_block(sha);
    }
  }

  return 1;
}

int sha224_hash(Sha224 *sha) {
  // append 1 to end of message
  sha->msg_block[sha->block_idx++] = 0x80;

  // process last block of data if necessary and zero out rest of block
  if (sha->block_idx < BLOCK_SIZE - 8) {
    while (sha->block_idx < BLOCK_SIZE - 8) {
      sha->msg_block[sha->block_idx++] = 0;
    }
  } else {
    while (sha->block_idx < BLOCK_SIZE) {
      sha->msg_block[sha->block_idx++] = 0;
    }
    compute_block(sha);
    while (sha->block_idx < 56) {
      sha->msg_block[sha->block_idx++] = 0;
    }
  }

  // copy bit count into 64 bit word at end of block
  sha->msg_block[56] = sha->bit_cnt >> 56;
  sha->msg_block[57] = sha->bit_cnt >> 48;
  sha->msg_block[58] = sha->bit_cnt >> 40;
  sha->msg_block[59] = sha->bit_cnt >> 32;
  sha->msg_block[60] = sha->bit_cnt >> 24;
  sha->msg_block[61] = sha->bit_cnt >> 16;
  sha->msg_block[62] = sha->bit_cnt >> 8;
  sha->msg_block[63] = sha->bit_cnt;

  compute_block(sha);

  // flip byte ordering to big endian and truncate final hash
  if (*(const unsigned char *)&endian == 0xff) {
    sha->msg_digest[0] = endian_reverse32(sha->msg_digest[0]);
    sha->msg_digest[1] = endian_reverse32(sha->msg_digest[1]);
    sha->msg_digest[2] = endian_reverse32(sha->msg_digest[2]);
    sha->msg_digest[3] = endian_reverse32(sha->msg_digest[3]);
    sha->msg_digest[4] = endian_reverse32(sha->msg_digest[4]);
    sha->msg_digest[5] = endian_reverse32(sha->msg_digest[5]);
    sha->msg_digest[6] = endian_reverse32(sha->msg_digest[6]);
    sha->msg_digest[7] = 0;
  }

  return 1;
}

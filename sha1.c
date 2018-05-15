#include "shs.h"

static uint32_t endian = 0xaabcdeff;

// constants
static uint32_t K[] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};

static uint32_t initials[] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
                              0xc3d2e1f0};

#define BLOCK_SIZE 64  // 512 bit blocks

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define PARITY(x, y, z) ((x) ^ (y) ^ (z))

static uint32_t endian_reverse32(uint32_t n) {
  unsigned char* np = (unsigned char*)&n;
  return ((uint32_t)np[0] << 24) | ((uint32_t)np[1] << 16) |
         ((uint32_t)np[2] << 8) | (uint32_t)np[3];
}

static int compute_block(Sha1* sha) {
  unsigned int var_a;
  unsigned int var_b;
  unsigned int var_c;
  unsigned int var_d;
  unsigned int var_e;
  unsigned int W[80];
  unsigned int T1;

  // prepare message schedule
  for (int t = 0; t <= 15; t++) {
    W[t] = (sha->msg_block[t * 4]) << 24;
    W[t] |= (sha->msg_block[t * 4 + 1]) << 16;
    W[t] |= (sha->msg_block[t * 4 + 2]) << 8;
    W[t] |= (sha->msg_block[t * 4 + 3]);
  }

  for (int t = 16; t < 80; t++) {
    W[t] = ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
  }

  // initialize working variables
  var_a = sha->msg_digest[0];
  var_b = sha->msg_digest[1];
  var_c = sha->msg_digest[2];
  var_d = sha->msg_digest[3];
  var_e = sha->msg_digest[4];

  // do the math
  for (int t = 0; t < 80; t++) {
    unsigned int val;
    if (t >= 0 && t <= 19)
      val = CH(var_b, var_c, var_d) + K[0];
    else if (t >= 20 && t <= 39)
      val = PARITY(var_b, var_c, var_d) + K[1];
    else if (t >= 40 && t <= 59)
      val = MAJ(var_b, var_c, var_d) + K[2];
    else if (t >= 60 && t <= 79)
      val = PARITY(var_b, var_c, var_d) + K[3];

    T1 = ROTL(var_a, 5) + val + var_e + W[t];
    var_e = var_d;
    var_d = var_c;
    var_c = ROTL(var_b, 30);
    var_b = var_a;
    var_a = T1;
  }

  // compute intermediate hash value
  sha->msg_digest[0] += var_a;
  sha->msg_digest[1] += var_b;
  sha->msg_digest[2] += var_c;
  sha->msg_digest[3] += var_d;
  sha->msg_digest[4] += var_e;

  return 1;
}

Sha1* sha1_new() {
  Sha1* sha;
  sha = malloc(sizeof(Sha1));
  sha->block_idx = 0;
  sha->bit_cnt = 0;
  sha->msg_digest[0] = initials[0];
  sha->msg_digest[1] = initials[1];
  sha->msg_digest[2] = initials[2];
  sha->msg_digest[3] = initials[3];
  sha->msg_digest[4] = initials[4];

  return sha;
}

int sha1_load(Sha1* sha, const unsigned char data[], const unsigned int len) {
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

int sha1_hash(Sha1* sha) {
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

  // flip byte ordering to big endian
  if (*(const unsigned char*)&endian == 0xff) {
    sha->msg_digest[0] = endian_reverse32(sha->msg_digest[0]);
    sha->msg_digest[1] = endian_reverse32(sha->msg_digest[1]);
    sha->msg_digest[2] = endian_reverse32(sha->msg_digest[2]);
    sha->msg_digest[3] = endian_reverse32(sha->msg_digest[3]);
    sha->msg_digest[4] = endian_reverse32(sha->msg_digest[4]);
  }

  return 1;
}
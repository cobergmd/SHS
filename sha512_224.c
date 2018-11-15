#include "shs.h"

static uint32_t endian = 0xaabcdeff;

// constants
static unsigned long long K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

static unsigned long long initials[8] = {
    0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82,
    0x679dd514582f9fcf, 0x0f6d2b697bd44da8, 0x77e36f7304c48942,
    0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1};

#define BLOCK_BYTE_CNT 128  // 1024 bits

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR(x, n) (((x) >> (n)))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define USIG0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define USIG1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define LSIG0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define LSIG1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

static uint64_t endian_reverse64(uint64_t n) {
  unsigned char *np = (unsigned char *)&n;
  return ((uint64_t)np[0] << 56) | ((uint64_t)np[1] << 48) |
         ((uint64_t)np[2] << 40) | ((uint64_t)np[3] << 32) |
         ((uint64_t)np[4] << 24) | ((uint64_t)np[5] << 16) |
         ((uint64_t)np[6] << 8) | (uint64_t)np[7];
}

static int compute_block(Sha512_224 *sha) {
  unsigned long long var_a;
  unsigned long long var_b;
  unsigned long long var_c;
  unsigned long long var_d;
  unsigned long long var_e;
  unsigned long long var_f;
  unsigned long long var_g;
  unsigned long long var_h;

  unsigned long long W[80];
  unsigned long long T1;
  unsigned long long T2;

  // prepare message schedule
  for (int t = 0; t <= 15; t++) {
    W[t] = ((unsigned long long)sha->msg_block[t * 8]) << 56;
    W[t] |= ((unsigned long long)sha->msg_block[t * 8 + 1]) << 48;
    W[t] |= ((unsigned long long)sha->msg_block[t * 8 + 2]) << 40;
    W[t] |= ((unsigned long long)sha->msg_block[t * 8 + 3]) << 32;
    W[t] |= ((unsigned long long)sha->msg_block[t * 8 + 4]) << 24;
    W[t] |= ((unsigned long long)sha->msg_block[t * 8 + 5]) << 16;
    W[t] |= ((unsigned long long)sha->msg_block[t * 8 + 6]) << 8;
    W[t] |= ((unsigned long long)sha->msg_block[t * 8 + 7]);
  }

  for (int t = 16; t <= 79; t++) {
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
  for (int t = 0; t <= 79; t++) {
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

  sha->byte_idx = 0;

  return 1;
}

Sha512_224 *sha512_224_new() {
  Sha512_224 *sha;
  sha = malloc(sizeof(Sha512_224));
  sha->byte_idx = 0;
  sha->bit_cnt[0] = 0;
  sha->bit_cnt[1] = 0;
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

int sha512_224_load(Sha512_224 *sha, const unsigned char data[],
                const unsigned int len) {
  if (!len) return 0;

  sha->bit_cnt[0] += (unsigned long long)len * 8;
  if (sha->bit_cnt[0] < ((uint64_t)len * 8)) sha->bit_cnt[1]++;

  for (unsigned int i = 0; i < len; ++i) {
    sha->msg_block[sha->byte_idx++] = data[i];

    if (sha->byte_idx == BLOCK_BYTE_CNT) {
      compute_block(sha);
    }
  }

  return 1;
}

int sha512_224_hash(Sha512_224 *sha) {
  // append 1 to end of message
  sha->msg_block[sha->byte_idx++] = 0x80;

  // process last block of data if necessary and zero out rest of block
  if (sha->byte_idx < BLOCK_BYTE_CNT - 8) {
    while (sha->byte_idx < BLOCK_BYTE_CNT - 8) {
      sha->msg_block[sha->byte_idx++] = 0;
    }
  } else {
    while (sha->byte_idx < BLOCK_BYTE_CNT) {
      sha->msg_block[sha->byte_idx++] = 0;
    }
    compute_block(sha);
    while (sha->byte_idx < 56) {
      sha->msg_block[sha->byte_idx++] = 0;
    }
  }

  // copy bit count into last 128 bit block
  sha->msg_block[112] = sha->bit_cnt[1] >> 56;
  sha->msg_block[113] = sha->bit_cnt[1] >> 48;
  sha->msg_block[114] = sha->bit_cnt[1] >> 40;
  sha->msg_block[115] = sha->bit_cnt[1] >> 32;
  sha->msg_block[116] = sha->bit_cnt[1] >> 24;
  sha->msg_block[117] = sha->bit_cnt[1] >> 16;
  sha->msg_block[118] = sha->bit_cnt[1] >> 8;
  sha->msg_block[119] = sha->bit_cnt[1];

  sha->msg_block[120] = sha->bit_cnt[0] >> 56;
  sha->msg_block[121] = sha->bit_cnt[0] >> 48;
  sha->msg_block[122] = sha->bit_cnt[0] >> 40;
  sha->msg_block[123] = sha->bit_cnt[0] >> 32;
  sha->msg_block[124] = sha->bit_cnt[0] >> 24;
  sha->msg_block[125] = sha->bit_cnt[0] >> 16;
  sha->msg_block[126] = sha->bit_cnt[0] >> 8;
  sha->msg_block[127] = sha->bit_cnt[0];

  compute_block(sha);

  // flip byte ordering to big endian and truncate to 224 bits
  if (*(const unsigned char *)&endian == 0xff) {
    sha->msg_digest[0] = endian_reverse64(sha->msg_digest[0]);
    sha->msg_digest[1] = endian_reverse64(sha->msg_digest[1]);
    sha->msg_digest[2] = endian_reverse64(sha->msg_digest[2]);
    sha->msg_digest[3] =
        endian_reverse64(sha->msg_digest[3] &= 0xffffffff00000000);
    sha->msg_digest[4] = 0;
    sha->msg_digest[5] = 0;
    sha->msg_digest[6] = 0;
    sha->msg_digest[7] = 0;
  }

  return 1;
}
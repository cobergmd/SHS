#include <memory.h>
#include "shs.h"
#include "unittest.h"

static char *test_sha1_nsit_test1()
{
  unsigned char nsit_tst1[] = {"abc"};
  unsigned char nsit_hash[] = {0xa9,0x99,0x3e,0x36,
                               0x47,0x06,0x81,0x6a,
                               0xba,0x3e,0x25,0x71,
                               0x78,0x50,0xc2,0x6c,
                               0x9c,0xd0,0xd8,0x9d};
  Sha1 *sha = sha1_new();
  sha1_load(sha, nsit_tst1, strlen((const char *)nsit_tst1));
  sha1_hash(sha);

  test_true("NIST SHA-1 Test 1", !memcmp(sha->msg_digest, nsit_hash, 20));
  return 0;
}

static char *test_sha256_nsit_test1()
{
  unsigned char nsit_tst1[] = {"abc"};

  unsigned char nsit_hash1[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41,
                                  0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3,
                                  0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

  Sha256 *data = sha256_new();
  sha256_load(data, nsit_tst1, strlen((const char *)nsit_tst1));
  sha256_hash(data);

  test_true("NIST SHA-256 Test 1", !memcmp(data->msg_digest, nsit_hash1, 32));

  for (int i = 0; i < 8; i++) {
    printf("%x", data->msg_digest[i]);
  }
  printf("\n");

  return 0;
}

static char *test_sha256_nsit_test2()
{
  unsigned char nsit_tst2[] = {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};

  unsigned char nsit_hash2[32] = {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0,
                                  0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59,
                                  0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1};

  Sha256 *data = sha256_new();
  sha256_load(data, nsit_tst2, strlen((const char *)nsit_tst2));
  sha256_hash(data);

  test_true("NIST SHA-256 Test 2", !memcmp(data->msg_digest, nsit_hash2, 32));

  for (int i = 0; i < 8; i++) {
    printf("%x", data->msg_digest[i]);
  }
  printf("\n");

  return 0;
}

static char *test_sha256_nsit_test3()
{
  unsigned char nsit_tst3[] = {"aaaaaaaaaa"};

  unsigned char nsit_hash3[32] = {0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1,
                                  0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48,
                                  0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0};

  Sha256 *data = sha256_new();
  for (int i = 0; i < 100000; i++) {
    sha256_load(data, nsit_tst3, strlen((const char *)nsit_tst3));
  }
  sha256_hash(data);

  test_true("NIST SHA-256 Test 3", !memcmp(data->msg_digest, nsit_hash3, 32));

  for (int i = 0; i < 8; i++) {
    printf("%x", data->msg_digest[i]);
  }
  printf("\n");

  return 0;
}

static char *test_sha224_nsit_test1() {
  unsigned char nsit_str[] = {"abc"};
  unsigned char nsit_hash[] = {0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22,
                               0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
                               0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7,
                               0xe3, 0x6c, 0x9d, 0xa7};

  Sha224 *sha = sha224_new();
  sha224_load(sha, nsit_str, strlen((const char*)nsit_str));
  sha224_hash(sha);

  test_true("NIST SHA-224 Test 1", !memcmp(sha->msg_digest, nsit_hash, 28));
  return 0;
}

static char *test_sha512_nsit_test1() {
  unsigned char nsit_tst1[] = {"abc"};

  unsigned char nsit_hash1[64] = {
      0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73,
      0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9,
      0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21,
      0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23,
      0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8,
      0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
  };

  Sha512 *data = sha512_new();
  sha512_load(data, nsit_tst1, strlen((const char *)nsit_tst1));
  sha512_hash(data);

  test_true("NIST SHA-512 Test 1", !memcmp(data->msg_digest, nsit_hash1, 64));

  for (int i = 0; i < 8; i++) {
    printf("%x", data->msg_digest[i]);
  }
  printf("\n");

  return 0;
}

static char *run_tests() {
  test_run(test_sha1_nsit_test1);
  test_run(test_sha256_nsit_test1);
  test_run(test_sha256_nsit_test2);
  test_run(test_sha256_nsit_test3);
  test_run(test_sha224_nsit_test1);
  test_run(test_sha512_nsit_test1);
  return 0;
}

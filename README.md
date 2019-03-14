# Secure Hash

My naive implementations of selected algorithms from the NIST Secure Hash Standard.

# 180-4 Specification

https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf

# Tests

https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data

https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

# Functions

## SHA-1

```
  Sha1 *sha = sha1_new();
  sha1_load(sha, nsit_tst1, strlen((const char *)nsit_tst1));
  sha1_hash(sha);
```

## SHA-224

## SHA-256




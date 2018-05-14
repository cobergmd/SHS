#include <stdio.h>
#include <stddef.h>

#define test_true(message, exp) \
  do {                          \
    if (!(exp)) return message; \
  } while (0)
#define test_false(message, exp) \
  do {                           \
    if ((exp)) return message;   \
  } while (0)
#define test_equal(message, exp1, exp2)  \
  do {                                   \
    if (!(exp1 == exp2)) return message; \
  } while (0)
#define test_null(message, exp1) \
  do {                               \
    if ((exp1 != NULL)) return message; \
  } while (0)
#define test_not_null(message, exp1) \
  do {                               \
    if ((exp1 == NULL)) return message; \
  } while (0)
#define test_run(test)           \
  do {                           \
    char *message = test();      \
    tests_run++;                 \
    if (message) return message; \
  } while (0)

int tests_run = 0;
static char *run_tests();

int main(int argc, char **argv) {
  printf("Running Unit Tests...\n");
  char *result = run_tests();
  if (result != 0) {
    printf("[FAIL] %s\n", result);
  } else {
    printf("[SUCCESS]\n");
  }
  printf("Total Unit Tests Run: %d\n", tests_run);

  return result != 0;
}

#include <stdlib.h>
#include <stdio.h>

#define TEST_FAIL(...)				\
  do {						\
    fprintf(stderr, "FAIL " __VA_ARGS__);	\
    exit(1);					\
  } while (0)

#define TEST_ASSERT(c)				\
  do {						\
    if (!(c)) TEST_FAIL( "failed: " #c);	\
  } while (0)


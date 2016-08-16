
#include <stdlib.h>
#include <stdio.h>

#define TEST_LOC(lnum) __FILE__ ":" #lnum ":"
#define TEST_LOC_(x) TEST_LOC(x)

#define TEST_FAIL(...)				\
  do {						\
    fprintf(stderr, "FAIL " TEST_LOC_(__LINE__) __VA_ARGS__);	\
    exit(1);					\
  } while (0)

#define TEST_ASSERT(c)				\
  do {						\
    if (!(c)) TEST_FAIL( "failed: " #c);	\
  } while (0)


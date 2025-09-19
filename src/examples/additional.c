#include <stdio.h>
#include <stdlib.h>
#include "user/syscall.h"

int
main (int argc, char *argv[])
{
  if (argc != 4) {
    printf("usage: additional <n> <a> <b> <c> <d>\n");
    return EXIT_FAILURE;
  }

  int a = atoi(argv[1]);
  int b = atoi(argv[2]);
  int c = atoi(argv[3]);
  int d = atoi(argv[4]);

  int fib = fibonacci(a);
  int mx  = max_of_four_int(a, b, c, d);

  printf("%d %d\n", fib, mx);
  return EXIT_SUCCESS;
}
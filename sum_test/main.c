#include <stdio.h>

int main ()
{
  int i, sum;

  sum = 0;
  for (i = 1; i <=100; i++)
    sum += i;

  printf ("sum [1 to 100] = %d\n");
  
  return 0;
}

#include <stdio.h>
#include "utils.h"

void print_hex(const char *label, const uint8_t *buf, size_t len)
{
  size_t i;
  if(label)
    printf("%s: ", label);
  for(i = 0; i < len; ++i)
    printf("%02x", buf[i]);
  printf("\n");
}

void secure_zeroize(void *v, size_t n)
{
  volatile uint8_t *p = (volatile uint8_t *)v;
  while(n--) {
    *p++ = 0;
  }
}

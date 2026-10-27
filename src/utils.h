#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

void print_hex(const char *label, const uint8_t *buf, size_t len);
void secure_zeroize(void *v, size_t n);

#endif

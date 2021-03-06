/*
 * Copyright CEA/DAM/DIF (2013)
 * Contributor: Dominique Martinet <dominique.martinet@cea.fr>
 *
 * This file is part of the space9 9P userspace library.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with space9.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "../bitmap.h"

void print_map(bitmap_t *map, size_t size) {
	int i;
	printf("map:");
	for (i=0; i < WORD_OFFSET(size); i++) {
		printf(" %016"PRIx64, map[i]);
	}
	if (BIT_OFFSET(size))
		printf(" %016"PRIx64, map[i]);

	printf("\n");
}

#define DEFAULT_SIZE 1024

int main(int argc, char **argv) {
	bitmap_t *test_bitmap;
	int i, j, size;

	size = 0;
	if (argc > 1)
		size = atoi(argv[1]);

	if (size == 0)
		size = DEFAULT_SIZE;

	test_bitmap=malloc(size/8 + ((size % 8 == 0) ? 0 : 1));
	memset(test_bitmap, 0, size/8 + ((size % 8 == 0) ? 0 : 1));

	for (i=0; i< 4; i++) {
		printf("%u\n", get_and_set_first_bit(test_bitmap, size));
	}
	print_map(test_bitmap, size);
	printf("bitcount: %u\n", bitcount(test_bitmap, size));

	for (i=0; i< size; i++) {
		printf("%u\n", get_and_set_first_bit(test_bitmap, size));
	}
	print_map(test_bitmap, size);
	printf("bitcount: %u\n", bitcount(test_bitmap, size));

	for (j=0; j<WORD_OFFSET(size); j++) {
		for (i=0; i<4; i++) {
			clear_bit(test_bitmap, i+12+j*BITS_PER_WORD);
		}
	}
	print_map(test_bitmap, size);
	printf("bitcount: %u\n", bitcount(test_bitmap, size));

	for (i=0; i< 4 * WORD_OFFSET(size); i++) {
		printf("%u\n", get_and_set_first_bit(test_bitmap, size));
	}
	print_map(test_bitmap, size);
	printf("bitcount: %u\n", bitcount(test_bitmap, size));

	return 0;
}

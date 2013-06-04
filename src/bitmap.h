/* bitmap */

#ifndef BITMAP_H
#define BITMAP_H

#define ffsll __builtin_ffsll
#define popcountll __builtin_popcountll

typedef uint64_t bitmap_t;
#define BITS_PER_WORD  64
#define WORD_OFFSET(b) ((b) / BITS_PER_WORD)
#define BIT_OFFSET(b)  ((b) % BITS_PER_WORD)
#define BITMAP_SIZE(s)  (

static inline void set_bit(bitmap_t *map, int n) { 
	map[WORD_OFFSET(n)] |= (1ULL << BIT_OFFSET(n));
}

static inline void clear_bit(bitmap_t *map, int n) {
	map[WORD_OFFSET(n)] &= ~(1ULL << BIT_OFFSET(n)); 
}

static inline int get_bit(bitmap_t *map, int n) {
	bitmap_t bit = map[WORD_OFFSET(n)] & (1ULL << BIT_OFFSET(n));
	return bit != 0; 
}

static inline uint32_t get_and_set_first_bit(bitmap_t *map, uint32_t max) {
	uint32_t maxw, i;

	maxw = max / BITS_PER_WORD;
	i = 0;

	while (map[i] == ~0L && i < maxw)
		i++;

	if (i == maxw) {
		if (BIT_OFFSET(max) != 0) {
			i = maxw*BITS_PER_WORD + ffsll(~map[maxw]) - 1;
			if (i < max)
				set_bit(map, i);
			else
				i = max;
		} else {
			i = max;
		}

		return i;
	}

	i = i*BITS_PER_WORD + ffsll(~map[i]) - 1;
	set_bit(map, i);
	return i;
}

static inline uint32_t bitcount(bitmap_t *map, uint32_t max) {
	uint32_t count, maxw, i;

	count = 0;
	maxw = max / BITS_PER_WORD;
	i = 0;

	for (i=0; i < maxw; i++)
		count += popcountll(map[i]);

	// Assume the end of the bitmap is padded with 0
	if (BIT_OFFSET(max) != 0)
		count += popcountll(map[maxw]);

	return count;
}

#endif

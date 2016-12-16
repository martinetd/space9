AM_CFLAGS = -g -Wall -Werror -I$(srcdir)/../../include -I$(srcdir)/..

noinst_PROGRAMS = test_bitmap test_utils find readwrite createtree liop

test_bitmap_SOURCES = test_bitmap.c
test_bitmap_LDADD = ../libspace9.la

test_utils_SOURCES = test_utils.c
test_utils_LDADD = ../libspace9.la

find_SOURCES = find.c
find_LDADD = ../libspace9.la -lpthread

readwrite_SOURCES = readwrite.c
readwrite_LDADD = ../libspace9.la -lpthread

createtree_SOURCES = createtree.c
createtree_LDADD = ../libspace9.la -lpthread

liop_SOURCES = liop.c
liop_LDADD = ../libspace9.la

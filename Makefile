# vim: set noexpandtab:

.DEFAULT_GOAL := all
LDIR=mbedtls/library
IDIR=mbedtls/include
CC=gcc
gcc_warn=-DDEBUG_UNUSED -Wswitch -DPEDANTIC -pedantic -Wno-long-long -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wsign-compare -Wmissing-prototypes -Wshadow -Wformat -Wtype-limits -Wundef #-Werror
CFLAGS=-g3 -O0 $(gcc_warn) -I$(IDIR) -L$(LDIR)

# objects dir
OBJDIR      = obj

# Extensions of files to delete when cleaning
CLEANEXTS   = o a

# Target file and install directory
OUTPUTFILE  = libcmpcl.a
INSTALLDIR  = ./

# Default target
.PHONY: all
all: $(OUTPUTFILE)

_OBJ = cmpcl_write.o cmpcl_read.o cmpcl_lib.o cmpcl_ses.o cmpcl_ctx.o cmpcl_trans_nombed.o
OBJ = $(patsubst %, $(OBJDIR)/%, $(_OBJ))

_DEP = cmpcl.h cmpcl_int.h
DEP = $(patsubst %, ./%, $(_DEP))

$(OBJDIR)/%.o: ./%.c $(DEP)
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: all
all: $(OUTPUTFILE) mbedtls/library/libmbedcrypto.a

# Build libcmpcl.a from all object files
$(OUTPUTFILE): $(OBJ)
	ar ru $@ $^
	ranlib $@

.PHONY: clean
clean:
	for file in $(CLEANEXTS); do rm -f *.$$file $(OBJDIR)/*.$$file; done

mbedtls/library/libmbedcrypto.a:
	make -C mbedtls

.PHONY: distclean
distclean: clean
	make -C mbedtls clean

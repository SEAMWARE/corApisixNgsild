#
# makefile - libngsildpep.so: the decision of the APISIX NGSI-LD plugin - coraine's fdsc.so code, compiled from
# its sources (CORAINE: a coraine checkout), with the Cor-Libs (COR_LIBS: their parent directory) linked in
#
# Copyright 2026 Seamware
# SPDX-License-Identifier: Apache-2.0
#
COR_LIBS     ?= ..
CORAINE      ?= $(COR_LIBS)/coraine
FDSC         := $(CORAINE)/src/plugins/auth/fdsc

FDSC_SOURCES := fdsc.c fdscBase64.c fdscIdentity.c fdscJwt.c fdscKeys.c fdscPolicy.c fdscTokenCache.c
SOURCES      := src/ngsildPep.c src/fdscFetchFile.c $(addprefix $(FDSC)/,$(FDSC_SOURCES))
LIBS_STATIC  := corJson corTree corAlloc corLog corBase
ARCHIVES     := $(foreach l,$(LIBS_STATIC),$(COR_LIBS)/$(l)/obj/release/lib$(l).a)

CFLAGS       := -O2 -Wall -Werror -fPIC -fvisibility=hidden -I$(COR_LIBS) -I$(CORAINE)/src/lib -I$(FDSC) -Isrc
LDFLAGS      := -shared -Wl,--no-undefined -Wl,--exclude-libs,ALL
LDLIBS       := -lcrypto -lpthread -lm

OBJDIR       := obj
OBJS         := $(patsubst %.c,$(OBJDIR)/%.o,$(notdir $(SOURCES)))

vpath %.c src $(FDSC)

all: libngsildpep.so

libngsildpep.so: $(OBJS) $(ARCHIVES)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -Wl,--start-group $(ARCHIVES) -Wl,--end-group $(LDLIBS)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) libngsildpep.so

.PHONY: all clean

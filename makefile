.PHONY: all clean

CC = cc
CFLAGS += -O2 -std=c89
CFLAGS += -Wall -Wextra -pedantic
CFLAGS += -I. -Icipher -Imode

CPHRCFILES = $(wildcard cipher/*/*.c)
MODECFILES = $(wildcard   mode/*/*.c)

OBJDIR = bin
OBJCPHRDIR = $(OBJDIR)/cipher
OBJMODEDIR = $(OBJDIR)/mode

OBJCDIRS = $(addprefix $(OBJCPHRDIR)/,$(notdir $(basename $(CPHRCFILES))))
OBJMDIRS = $(addprefix $(OBJMODEDIR)/,$(notdir $(basename $(MODECFILES))))

OBJS += $(OBJDIR)/test.o
OBJS += $(patsubst %.c,$(OBJDIR)/%.o,$(CPHRCFILES))
OBJS += $(patsubst %.c,$(OBJDIR)/%.o,$(MODECFILES))

ifeq ($(CC),clang)
CFLAGS += -Wno-newline-eof
endif

all: $(OBJS)
	$(CC) -o tp $^

clean:
	rm -fr *.exe $(OBJDIR)/*

$(OBJS): | $(OBJDIR) $(OBJCPHRDIR) $(OBJMODEDIR) $(OBJCDIRS) $(OBJMDIRS)

$(OBJDIR):
	mkdir $(OBJDIR)
$(OBJCPHRDIR):
	mkdir $(OBJCPHRDIR)
$(OBJMODEDIR):
	mkdir $(OBJMODEDIR)
$(OBJCDIRS):
	mkdir $(OBJCDIRS)
$(OBJMDIRS):
	mkdir $(OBJMDIRS)

$(OBJDIR)/%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(OBJCPHRDIR)/%/%.o: cipher/%/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(OBJMODEDIR)/%/%.o: mode/%/%.c
	$(CC) -c -o $@ $< $(CFLAGS)
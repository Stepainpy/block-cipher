.PHONY: all clean

CC = cc
CFLAGS += -O2 -std=c89
CFLAGS += -Wall -Wextra -pedantic
CFLAGS += -I. -Icipher -Imode

CCFILES = $(wildcard cipher/*/*.c)
MCFILES = $(wildcard   mode/*/*.c)

OBJDIR = bin
OBJCDIR = $(OBJDIR)/cipher
OBJMDIR = $(OBJDIR)/mode

OBJCDIRS = $(addprefix $(OBJCDIR)/,$(notdir $(basename $(CCFILES))))
OBJMDIRS = $(addprefix $(OBJMDIR)/,$(notdir $(basename $(MCFILES))))

OBJS += $(OBJDIR)/test.o
OBJS += $(patsubst %.c,$(OBJDIR)/%.o,$(CCFILES))
OBJS += $(patsubst %.c,$(OBJDIR)/%.o,$(MCFILES))

ifeq ($(CC),clang)
CFLAGS += -Wno-newline-eof
endif

all: $(OBJS)
	$(CC) -o tp $^

clean:
ifneq ($(wildcard $(OBJDIR)/.*),)
	rm -fr *.exe $(OBJDIR)/*
	rmdir $(OBJDIR)
else
	@echo "Already cleaned"
endif

$(OBJS): | $(OBJDIR) $(OBJCDIRS) $(OBJMDIRS)

$(OBJDIR):
	mkdir $(OBJDIR)
$(OBJCDIRS):
	mkdir -p $(OBJCDIRS)
$(OBJMDIRS):
	mkdir -p $(OBJMDIRS)

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJCDIR)/%/%.o: cipher/%/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJMDIR)/%/%.o:   mode/%/%.c
	$(CC) $(CFLAGS) -c -o $@ $<
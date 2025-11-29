#
# Makefile for chat server
#
CC	= gcc
EXECUTABLES=chatClient2 chatServer2 directoryServer2
INCLUDES	= $(wildcard *.h)
SOURCES	= $(wildcard *.c)
DEPS		= $(INCLUDES)
OBJECTS	= $(SOURCES:.c=.o)
OBJECTS	+= $(SOURCES:.c=.dSYM*)
EXTRAS	= $(SOURCES:.c=.exe*)
LIBS		=
LDFLAGS	=
CFLAGS	= -g -ggdb -std=c99 \
				-Wuninitialized -Wunused -Wunused-macros -Wunused-variable \
				-Wunused-function -Wunused-but-set-parameter \
				-Wignored-qualifiers -Wshift-negative-value \
				-Wmain -Wreturn-type \
				-Winit-self -Wimplicit-int -Wimplicit-fallthrough \
				-Wparentheses -Wdangling-else -Wfatal-errors \
				-Wreturn-type -Wredundant-decls -Wswitch-default -Wshadow \
				-Wformat=2 -Wformat-nonliteral -Wformat-y2k -Wformat-security
CFLAGS	+= -ggdb3
#CFLAGS	+= -Wconversion
#CFLAGS	+= -Wc99-c11-compat -Wmaybe-uninitialized \
					-Wformat-truncation=2 -Wstringop-truncation \
					-Wformat-overflow=2 -Wformat-signedness

all:	chat2

chat2:	$(EXECUTABLES)


chatClient2: chatClient2.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $<

chatServer2: chatServer2.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $<

directoryServer2: directoryServer2.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $<

# Clean up the mess we made
.PHONY: clean
clean:
	@-rm -rf $(OBJECTS) $(EXECUTABLES) $(EXTRAS)

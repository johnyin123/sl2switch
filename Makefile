ifndef EXE
	EXE=indb
endif

UUID:=$(shell cat /proc/sys/kernel/random/uuid | tr '-' '_')
GIT_VERSION := $(shell git --no-pager describe --tags --always 2>/dev/null || echo "Not a git repository")
GIT_COMMIT  := $(shell git rev-parse --verify HEAD 2>/dev/null || echo "Not a git repository")
GIT_DATE    := $(firstword $(shell git --no-pager show --date=iso-strict --format="%ad" --name-only 2>/dev/null || echo "1970-01-01T00:00:00+08:00"))
BUILD_DATE  := $(shell date --iso=seconds)
PANDOCDOC   := pandoc --toc --number-sections --latex-engine=xelatex -V lang=frenchb -V fontsize=11pt -V geometry:margin=3cm -V papersize=a4paper
DOCX        := $(patsubst %.md,%.md.docx,$(wildcard *.md))
CC          := $(CROSS_COMPILE)gcc #-std=c99
STRIP       := $(CROSS_COMPILE)strip
RM          := rm -f

DEBUG_FLAG+=-Wall

INCFILE=.make.inc
ifeq ($(INCFILE), $(wildcard $(INCFILE)))
include $(INCFILE)
# .make.inc -->
# EXE=ffff
# DIRS=. event
# CFLAGS+=-D_GNU_SOURCE -D__USE_XOPEN -O2 -march=native -mfpmath=sse  -Ofast -flto -march=native -funroll-loops
# LIBFLAGS+=-lluajit -lhiredis -lsqlite3 -lm -ldl -lpthread#`pkg-config --libs libssl` 
# LDFLAGS+=#-static#-Wl,-Bstatic -libc -Wl,-Bdynamic
# INC_PATH+=#-I../deps/LuaJIT-2.0.4/src -I../deps/hiredis
# LIB_PATH+=#-L../deps/LuaJIT-2.0.4/src -L../deps/hiredis
endif

ifeq ("$(origin DIRS)", "undefined")
DIRS=.
endif

ifdef DEBUG
	DEBUG_FLAG+=-ggdb -D_DEBUG=1 
else 
	DEBUG_FLAG+=-O3 -fomit-frame-pointer -pipe
endif

SRC = $(foreach dir,$(DIRS),$(wildcard $(dir)/*.c))
OBJ=$(SRC:.c=.o)
#SRCPP=$(wildcard *.cpp)
#OBJ += $(foreach file, $(SRCPP), $(file:%.cpp=%.o))

%.o: %.c 
	@echo -n "\033[1;31m"
	$(CC) $(CFLAGS) $(DEBUG_FLAG) $(INC_PATH) -o $@ -c $<
	@echo -n "\033[m"

%.md.docx : %.md
	$(PANDOCDOC) $< -o $@

.PHONY : all
all: $(EXE)

$(EXE): $(OBJ) 
	$(CC) $(OBJ) $(DEBUG_FLAG) $(LIB_PATH) $(LDFLAGS) -o $@ $(LIBFLAGS)

.PHONY : clean
clean:
	-$(RM) $(OBJ) $(EXE) $(DOCX)

run:
	@echo run $(filter-out $@,$(MAKECMDGOALS))
%:
	@:

bz2: clean
	cd .. && tar cv `basename $(PWD)` | bzip2 > `basename $(PWD)`-`date +%Y%m%d-%H%M`.tar.bz2

help:
	@echo "clean/bz2/version/gprof/gcov/coverage/help/run/docs/git_all/git_show"
	@echo "export DEBUG=1;make"
	@echo "make DEBUG=1"
	@echo "     1. gprof $(EXE) gmon.out -p 得到每个函数占用的执行时间"
	@echo "     2. gprof $(EXE) gmon.out -q 得到call graph"
	@echo "     3. gprof $(EXE) gmon.out -A 得到一个带注释的“源代码清单”"
	@echo "demo build rpm package: 1.make install DESTDIR=$(pwd)/bin/"
	@echo "2. fpm -s dir -t rpm -C ~/nginx-1.13.0/bin/ --name nginx_xikang --version 1.13.0 --iteration 1 --depends pcre --depends zlib --description \"nginx with openssl,other modules\" ."



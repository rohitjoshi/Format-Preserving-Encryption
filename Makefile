CC=clang
cc=clang
#CFLAGS = -arch arm64 -O2 -Wall -fPIC -I/opt/homebrew/Cellar/openssl@3/3.1/include/openssl
#CFLAGS =  -O2 -Wall -fPIC -I/opt/homebrew/Cellar/openssl@3/3.1/include/openssl
CFLAGS =  -O2 -Wall -fPIC
SO_LINKS =  -lm -lcrypto
#SO_LINKS = -arch arm64 -lm -lcrypto

LIB = libfpe.a libfpe.so
EXAMPLE_SRC = example.c
EXAMPLE_EXE = example
OBJS = src/ff1.o src/ff3.o src/fpe_locl.o src/ff1_native_128.o src/ff3_native_128.o

all: $(LIB) $(EXAMPLE_EXE)

libfpe.a: $(OBJS)
	ar rcs $@ $(OBJS)

libfpe.so: $(OBJS)
	cc -shared -fPIC -W $(OBJS) $(SO_LINKS) -o $@
	#cc -shared -fPIC -Wl,-install_name,libfpe.so $(OBJS) $(SO_LINKS) -o $@

.PHONY = all clean

src/ff1.o: src/ff1.c
	cc $(CFLAGS) -c src/ff1.c -o $@

src/ff1_native_128.o: src/ff1_native_128.c
	cc $(CFLAGS) -c src/ff1_native_128.c -o $@

src/ff3.o: src/ff3.c
	cc $(CFLAGS) -c src/ff3.c -o $@

src/ff3_native_128.o: src/ff3_native_128.c
	cc $(CFLAGS) -c src/ff3_native_128.c -o $@

src/fpe_locl.o: src/fpe_locl.c
	cc $(CFLAGS) -c src/fpe_locl.c -o $@

$(EXAMPLE_EXE): $(EXAMPLE_SRC) $(LIB)
	cc -W  $(EXAMPLE_SRC) -L. -lfpe -Isrc -O2 -o $@
	#gcc -Wl,-rpath=\$$ORIGIN $(EXAMPLE_SRC) -L. -lfpe -Isrc -O2 -o $@

clean:
	rm $(OBJS) $(EXAMPLE_EXE) $(LIB)


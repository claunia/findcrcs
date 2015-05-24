BINARY := findcrcs

ifeq ($(OS), Windows_NT)
	BINARY := $(BINARY).exe
endif

all: findcrcs

clean:
	rm $(BINARY)

findcrcs: findcrcs.cc md5.c md5.h crcutil-1.0
	g++ -O3 -Wall -mcrc32 -o $(BINARY) findcrcs.cc md5.c crcutil-1.0/examples/interface.cc crcutil-1.0/code/*.cc -Icrcutil-1.0/code -Icrcutil-1.0/tests -Icrcutil-1.0/examples
	strip $(BINARY)

crcutil-1.0: crcutil-1.0.tar.gz
	tar xfz crcutil-1.0.tar.gz
	chmod -R og-w+rX crcutil-1.0
	chown -R 0.0 crcutil-1.0
	touch crcutil-1.0

crcutil-1.0.tar.gz:
	wget -q -O - http://crcutil.googlecode.com/files/crcutil-1.0.tar.gz > crcutil-1.0.tar.gz
	touch crcutil-1.0.tar.gz

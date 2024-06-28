CC = gcc
CFLAGS = -Wall -fPIC -I/usr/include/security
LDFLAGS = -shared -lpam -lssl -lcrypto
TARGET = build/custom_pam_auth.so

SOURCES = custom_pam_auth.c
OBJECTS = $(SOURCES:%.c=build/%.o)

.PHONY: all clean

all: build_dir $(TARGET)

build_dir:
	mkdir -p build

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

build/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build

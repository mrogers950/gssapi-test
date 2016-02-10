TARGET = gssapi-test
LIBS = -lm -L/usr/local/lib -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/local/lib -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
CC = gcc
CFLAGS = -g -Wall -I/usr/local/include -Wshadow -Wstrict-prototypes \
	 -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings \
	 -Werror-implicit-function-declaration -fno-strict-aliasing

.PHONY: default all clean

default: $(TARGET)

OBJECTS = $(patsubst src/%.c, src/%.o, $(wildcard src/*.c))
HEADERS = $(wildcard src/*.h)

%.o: %.c $(HEADERS)
	    $(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	    $(CC) $(OBJECTS) -Wall $(LIBS) -o $@

clean:
	    -rm -f src/*.o
	        -rm -f $(TARGET)

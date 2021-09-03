# TODO: use cmake

ifeq ($(LIBWEBSOCKETS_LIB),)
	LIBWEBSOCKETS_LIB=-lwebsockets
endif
ifeq ($(LIBGLIB_LIB),)
	LIBGLIB_LIB=-lglib-2.0
endif
ifeq ($(LIBGLIB_INCLUDE),)
	LIBGLIB_INCLUDE=/usr/include/glib-2.0
endif
ifeq ($(LIBGLIB_LIB_INCLUDE),)
	LIBGLIB_LIB_INCLUDE=/usr/lib/x86_64-linux-gnu/glib-2.0/include
endif

CFLAGS=-I$(LIBGLIB_INCLUDE) -I$(LIBGLIB_LIB_INCLUDE)
LDLIBS=$(LIBGLIB_LIB) -lssl -lcrypto -lcap

CFLAGS+=-Wall -O2 -fPIC -pthread -I./ -I./include/
CFLAGS+= -D JSMN_STRICT -D JSMN_PARENT_LINKS -D JSMN_HEADER
CFLAGS+=$(EXTRA_CFLAGS)

JSMN_DEFINE := -D JSMN_STATIC -U JSMN_HEADER

obj = decimal.o auth.o currency.o client.o
obj += json-helpers.o order-book.o
exchange-obj = exchanges/bitstamp.o exchanges/coinbase.o exchanges/gemini.o exchanges/kraken.o

public-hdrs = include/exchg/exchanges.h include/exchg/exchg.h include/exchg/currency.h
public-hdrs += include/exchg/decimal.h include/exchg/orders.h

hdrs = $(public-hdrs) auth.h client.h json-helpers.h
hdrs += compiler.h net-backend.h order-book.h time-helpers.h
hdrs += exchanges/bitstamp.h exchanges/coinbase.h exchanges/kraken.h exchanges/gemini.h

test-obj = test/fake-net.o test/fake-gemini.o test/fake-kraken.o test/fake-bitstamp.o test/fake-coinbase.o
test-obj += test/json/kraken/pair-info.o
test-obj += test/json/bitstamp/pairs-info.o
test-obj += test/json/coinbase/products.o

public-test-hdrs = include/exchg/test.h

test-hdrs = $(public-test-hdrs) test/util.h test/fake-net.h test/fake-gemini.h
test-hdrs += test/fake-bitstamp.h test/fake-coinbase.h test/fake-kraken.h

examples = examples/trade/trade examples/print-book/print-book

tests = examples/trade/test json-test ob-test decimal-test

.PHONY: all tests examples clean

all: libexchg.a libexchg.so libexchg-test.a libexchg-test.so
examples: $(examples)
tests: $(tests)

libexchg.a: $(obj) $(exchange-obj) lws.o
	$(AR) rcs $@ $^
libexchg.so: $(obj) $(exchange-obj) lws.o
	$(CC) -shared -o $@ $^

libexchg-test.a: $(obj) $(exchange-obj) $(test-obj)
	$(AR) rcs $@ $^
libexchg-test.so: $(obj) $(exchange-obj) $(test-obj)
	$(CC) -shared -o $@ $^

examples/print-book/main.o: $(hdrs) examples/common.h
examples/print-book/print-book: examples/print-book/main.o
examples/print-book/print-book: examples/common.o libexchg.a
	$(CC) -o $@ $(CFLAGS) $^ $(LIBWEBSOCKETS_LIB) $(LDLIBS) -lncurses

examples/trade/trade.o: $(hdrs) examples/common.h examples/trade/trader.h
examples/trade/trader.o: $(hdrs) examples/common.h examples/trade/trader.h
examples/trade/main.o: $(hdrs) examples/common.h examples/trade/trader.h
examples/trade/test.o: $(hdrs) examples/common.h examples/trade/trader.h

examples/trade/trade: examples/trade/main.o examples/trade/trader.o
examples/trade/trade: examples/common.o libexchg.a
	$(CC) -o $@ $(CFLAGS) $^ $(LIBWEBSOCKETS_LIB) $(LDLIBS)

examples/trade/test: examples/common.o examples/trade/trader.o
examples/trade/test: examples/trade/test.o libexchg-test.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

test/json/kraken/pair-info.o: test/json/kraken/pair-info.json
	$(LD) -r -b binary -o $@ $^
test/json/bitstamp/pairs-info.o: test/json/bitstamp/pairs-info.json
	$(LD) -r -b binary -o $@ $^
test/json/coinbase/products.o: test/json/coinbase/products.json
	$(LD) -r -b binary -o $@ $^

decimal-test: decimal.o decimal-test.o
	$(CC) $(CFLAGS) -o $@ $^

json-test: json-helpers.h json-test.c json-helpers.o
	$(CC) $(CFLAGS) $(JSMN_DEFINE) -o $@ json-test.c json-helpers.o

ob-test: order-book.o order-book-test.o decimal.o
	$(CC) $(CFLAGS) -o $@ order-book.o decimal.o order-book-test.o \
	$(LDLIBS)

decimal.o: include/exchg/decimal.h
decimal-test.o: include/exchg/decimal.h
auth.o: auth.h
exchanges/bitstamp.o: $(hdrs)
exchanges/gemini.o: $(hdrs)
exchanges/kraken.o: $(hdrs)
exchanges/coinbase.o: $(hdrs)

client.o: $(hdrs) client.c
	$(CC) $(CFLAGS) $(JSMN_DEFINE) -c -o $@ client.c

json-helpers.o: json-helpers.h
order-book.o: include/exchg/decimal.h include/exchg/exchanges.h order-book.h
lws.o: net-backend.h

test/fake-net.o: $(hdrs) $(test-hdrs)

test/fake-bitstamp.o: $(hdrs) $(test-hdrs) test/fake-bitstamp.c
	$(CC) $(CFLAGS) $(JSMN_DEFINE) -c -o $@ test/fake-bitstamp.c

test/fake-gemini.o: $(hdrs) $(test-hdrs) test/fake-gemini.c
	$(CC) $(CFLAGS) $(JSMN_DEFINE) -c -o $@ test/fake-gemini.c

test/fake-kraken.o: $(hdrs) $(test-hdrs) test/fake-kraken.c
	$(CC) $(CFLAGS) $(JSMN_DEFINE) -c -o $@ test/fake-kraken.c

test/fake-coinbase.o: $(hdrs) $(test-hdrs) test/fake-coinbase.c
	$(CC) $(CFLAGS) $(JSMN_DEFINE) -c -o $@ test/fake-coinbase.c

examples/common.o: $(hdrs) examples/common.h

clean:
	@find test/ -name "*.o" -delete
	@find examples/ -name "*.o" -delete
	@rm -f libexchg.a libexchg-test.a libexchg.so libexchg-test.so *.o \
	exchanges/*.o $(examples) $(tests)

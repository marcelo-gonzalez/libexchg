# TODO: use cmake
dir = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

LIBWEBSOCKETS_LIB=./deps/build/libwebsockets/lib/libwebsockets.a
LIBGLIB_LIB=./deps/build/glib/glib/libglib-2.0.a

# for jsmn/jsmn.h
CFLAGS=-I./deps/

CFLAGS+=$(shell pkg-config --cflags ./deps/build/glib/meson-uninstalled/glib-2.0-uninstalled.pc --static)
CFLAGS+=-I./deps/build/libwebsockets/include/
CFLAGS+=$(shell pkg-config --cflags uuid)
CFLAGS+=$(shell pkg-config --cflags libssl)
CFLAGS+=$(shell pkg-config --cflags libcrypto)

LDLIBS=-lcap
LDLIBS+=$(shell pkg-config --libs ./deps/build/glib/meson-uninstalled/glib-2.0-uninstalled.pc --static)
LDLIBS+=$(shell pkg-config --libs uuid)
LDLIBS+=$(shell pkg-config --libs libssl)
LDLIBS+=$(shell pkg-config --libs libcrypto)

CFLAGS+=-Wall -O2 -fPIC -pthread -I./ -I./include/
CFLAGS+= -D JSMN_STRICT -D JSMN_PARENT_LINKS -D JSMN_HEADER
CFLAGS+=$(EXTRA_CFLAGS)

JSMN_DEFINE := -D JSMN_STATIC -U JSMN_HEADER

obj = decimal.o auth.o currency.o client.o
obj += json-helpers.o order-book.o buf.o
exchange-obj = exchanges/bitstamp.o exchanges/gemini.o exchanges/kraken.o
exchange-obj += exchanges/coinbase/cb-client.o exchanges/coinbase/cb-auth.o

public-hdrs = include/exchg/exchanges.h include/exchg/exchg.h include/exchg/currency.h
public-hdrs += include/exchg/decimal.h include/exchg/orders.h

hdrs = $(public-hdrs) auth.h b64.h client.h json-helpers.h
hdrs += compiler.h net-backend.h order-book.h time-helpers.h
hdrs += exchanges/bitstamp.h exchanges/coinbase/coinbase.h exchanges/kraken.h exchanges/gemini.h

LIBGLIB_HDR=./deps/glib/glib/glib.h
LIBWEBSOCKETS_HDR=./deps/libwebsockets/include/libwebsockets.h

hdrs += $(LIBGLIB_HDR)

test-obj = test/fake-net.o test/context.o
test-obj += test/fake-gemini.o test/fake-kraken.o test/fake-bitstamp.o test/fake-coinbase.o

public-test-hdrs = include/exchg/test.h

test-hdrs = $(public-test-hdrs) test/util.h test/fake-net.h test/fake-gemini.h
test-hdrs += test/fake-bitstamp.h test/fake-coinbase.h test/fake-kraken.h

examples = examples/trade/trade examples/print-book/print-book examples/simple/simple

tests = examples/trade/test json-test ob-test decimal-test

.PHONY: all tests examples clean libwebsockets libglib

all: libexchg.a libexchg-test.a
examples: $(examples)
tests: $(tests)

libwebsockets: libglib
	@if [ ! -d deps/build/libwebsockets/ ]; then \
		mkdir deps/build/libwebsockets; \
	fi; \
	if [ ! -f deps/build/libwebsockets/Makefile ]; then \
		cmake -B deps/build/libwebsockets -S deps/libwebsockets \
		-DLWS_WITH_GLIB=ON \
		-DGLIB_INCLUDE_DIRS="$(dir)/deps/glib/;$(dir)/deps/glib/glib/;$(dir)/deps/build/glib/;$(dir)/deps/build/glib/glib/" \
		-DGLIB_LIBRARIES=$(LIBGLIB_LIB) -DLWS_WITH_EVLIB_PLUGINS=0; \
	fi; \
	$(MAKE) -C deps/build/libwebsockets -j $(shell nproc)

$(LIBWEBSOCKETS_LIB): libwebsockets ;
$(LIBWEBSOCKETS_HDR): libwebsockets ;

libglib:
	@meson setup --default-library static deps/build/glib deps/glib; \
	meson compile -C deps/build/glib; \

$(LIBGLIB_HDR): libglib ;
$(LIBGLIB_LIB): libglib ;

libexchg.a: $(obj) $(exchange-obj) lws.o $(LIBWEBSOCKETS_LIB)
	$(AR) rcs $@ $^

libexchg-test.a: $(obj) $(exchange-obj) $(test-obj)
	$(AR) rcs $@ $^

examples/print-book/main.o: $(hdrs) examples/common.h
examples/print-book/print-book: examples/print-book/main.o
examples/print-book/print-book: examples/common.o libexchg.a
	$(CC) -o $@ -Wall -pthread -O2 -I./include $(EXTRA_CFLAGS) \
	$^ $(LIBWEBSOCKETS_LIB) $(LDLIBS) -lncurses

examples/trade/trade.o: $(hdrs) examples/common.h examples/trade/trader.h
examples/trade/trader.o: $(hdrs) examples/common.h examples/trade/trader.h
examples/trade/main.o: $(hdrs) examples/common.h examples/trade/trader.h
examples/trade/test.o: $(hdrs) examples/common.h examples/trade/trader.h

examples/trade/trade: examples/trade/main.o examples/trade/trader.o
examples/trade/trade: examples/common.o libexchg.a
	$(CC) -o $@ -Wall -pthread -O2 $(EXTRA_CFLAGS) \
	-I./include $^ $(LIBWEBSOCKETS_LIB) $(LDLIBS)

examples/simple/main.o: $(hdrs) examples/common.h
examples/simple/simple: examples/simple/main.o
examples/simple/simple: examples/common.o libexchg.a
	$(CC) -o $@ -Wall -pthread -O2 $(EXTRA_CFLAGS) \
	-I./include $^ $(LIBWEBSOCKETS_LIB) $(LDLIBS)

examples/trade/test: examples/common.o examples/trade/trader.o
examples/trade/test: examples/trade/test.o libexchg-test.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

decimal-test: decimal.o decimal-test.o
	$(CC) $(CFLAGS) -o $@ $^

json-test: json-helpers.h json-test.c json-helpers.o
	$(CC) $(CFLAGS) $(JSMN_DEFINE) -o $@ json-test.c json-helpers.o -lcrypto

ob-test: order-book.o order-book-test.o decimal.o
	$(CC) $(CFLAGS) -o $@ order-book.o decimal.o order-book-test.o \
	$(LDLIBS)

decimal.o: include/exchg/decimal.h
decimal-test.o: include/exchg/decimal.h
auth.o: auth.h $(LIBGLIB_HDR)
exchanges/bitstamp.o: $(hdrs)
exchanges/gemini.o: $(hdrs)
exchanges/kraken.o: $(hdrs)

coinbase-hdrs = exchanges/coinbase/cb-client.h exchanges/coinbase/cb-auth.h
exchanges/coinbase/cb-client.o: $(hdrs) $(coinbase-hdrs)
exchanges/coinbase/cb-auth.o: $(hdrs) $(coinbase-hdrs)

client.o: $(hdrs) client.c
	$(CC) $(CFLAGS) -c -o $@ client.c

buf.o: buf.h
json-helpers.o: json-helpers.c json-helpers.h
	$(CC) $(CFLAGS) $(JSMN_DEFINE) -c -o $@ json-helpers.c

order-book.o: include/exchg/decimal.h include/exchg/exchanges.h order-book.h $(LIBGLIB_HDR)
lws.o: net-backend.h $(LIBWEBSOCKETS_HDR)

test/fake-net.o: $(hdrs) $(test-hdrs)
test/context.o: $(hdrs) $(test-hdrs)

test/fake-bitstamp.o: $(hdrs) $(test-hdrs) test/fake-bitstamp.c
	$(CC) $(CFLAGS) -c -o $@ test/fake-bitstamp.c

test/fake-gemini.o: $(hdrs) $(test-hdrs) test/fake-gemini.c
	$(CC) $(CFLAGS) $(JSMN_DEFINE) -c -o $@ test/fake-gemini.c

test/fake-kraken.o: $(hdrs) $(test-hdrs) test/fake-kraken.c
	$(CC) $(CFLAGS) $(JSMN_DEFINE) -c -o $@ test/fake-kraken.c

test/fake-coinbase.o: $(hdrs) $(test-hdrs) test/fake-coinbase.c
	$(CC) $(CFLAGS) $(JSMN_DEFINE) -c -o $@ test/fake-coinbase.c

examples/common.o: $(hdrs) examples/common.h

clean:
	@find exchanges/ -name "*.o" -delete
	@find test/ -name "*.o" -delete
	@find examples/ -name "*.o" -delete
	@rm -f libexchg.a libexchg-test.a *.o $(examples) $(tests)

depsclean:
	@rm -rf deps/build

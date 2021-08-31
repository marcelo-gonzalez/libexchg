# A cryptocurrency exchange trading library

Very much a work-in-progress. API will be changing soon. Use at your own risk.

Main header is `include/exchg/exchg.h`. Look in `examples/` to get a sense for the API.

```console
hero@foo.bar:~/libexchg$ make examples
hero@foo.bar:~/libexchg$ ./examples/print-book/print-book -E kraken ethusd
```
## Dependencies
* [libglib](https://gitlab.gnome.org/GNOME/glib) (version 2.68 or later required)
* [libwebsockets](https://libwebsockets.org/git/libwebsockets/)
* [jsmn](https://github.com/zserge/jsmn)
* [libcrypto](https://git.openssl.org/?p=openssl.git;a=summary)

# A cryptocurrency exchange trading library

Very much a work-in-progress. API will be changing soon. Use at your own risk.

Main header is `include/exchg/exchg.h`. Look in `examples/` to get a sense for the API.

## Building
```console
hero@foo.bar:~$ git clone https://github.com/marcelo-gonzalez/libexchg && cd libexchg
hero@foo.bar:~/libexchg$ git submodule init && git submodule update
hero@foo.bar:~/libexchg$ sudo apt-get install cmake meson ninja-build
hero@foo.bar:~/libexchg$ make
hero@foo.bar:~/libexchg$ sudo apt-get install libncurses-dev
hero@foo.bar:~/libexchg$ make examples
hero@foo.bar:~/libexchg$ ./examples/print-book/print-book -E kraken ethusd
```

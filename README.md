# FAEST + half-tree

This is the implementation that uses the [half-tree technique](https://eprint.iacr.org/2022/1431)
to perform vector commitments used in the [FAEST signature scheme](https://faest.info/).

The implementation is based on the FAEST [reference implementation](https://github.com/faest-sign/faest-ref).
*This is proof-of-concept implementation.
It may contain bugs and security issues. Please do not use in production systems.*

Below is the original README.

# FAEST - Reference implementation

## Dependencies

For building:
* `meson` version 0.57 or newer
* `ninja` (depending on the build system generator selected via `meson`)

For tests:
* `boost` (unit test framework)
* `NTL`

On Debian-based Linux distributions:
```sh
apt install meson ninja-build # for build dependencies
apt install libboost-test-dev libntl-dev # for test dependencies
```

Both `meson` and `ninja` are also available via PyPI:
```sh
pip install meson ninja
```

## Building

```sh
mkdir build
cd build
meson ..
ninja
ninja test
```

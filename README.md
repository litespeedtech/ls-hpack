LS-HPACK: LiteSpeed HPACK Library
=================================

Description
-----------

LS-HPACK provides functionality to encode and decode HTTP headers using
HPACK compression mechanism specified in RFC 7541.

Documentation
-------------

The API is documented in include/ls/hpack.h.  To see usage examples,
see the unit tests.

Requirements
------------

To build LS-HPACK, you need CMake.  The library uses XXHASH at runtime.

Platforms
---------

The library has been tested on the following platforms:
- Linux
- FreeBSD

Copyright (c) 2018 LiteSpeed Technologies Inc

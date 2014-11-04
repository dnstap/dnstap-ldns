## Overview

This is `dnstap-ldns`, a reference utility that can decode [dnstap] encoded files. It uses the [ldns], [fstrm], and [protobuf-c] libraries to perform most of the heavy lifting.

## Building

First, install the dependencies: [ldns], [fstrm], and [protobuf-c].

Then, build and install `dnstap-ldns`:

    ./configure && make && make install

If building from a git checkout, the `autotools` must be installed. Run the `./autogen.sh` script first to bootstrap the build system.

## Synopsis

`dnstap` encoded files can be decoded and printed to `stdout` by running `dnstap-ldns -r` on the `dnstap` file.

The output format can be selected by passing additional command-line flags. The `-q` flag specifies the "quiet text" output format, which is compact (one line per `dnstap` frame), and excludes full DNS message details. The `-y` flag specifies a more verbose multi-document YAML-encoded output format that includes full DNS message details, as parsed by the [ldns] library.

[dnstap]:     http://dnstap.info/
[ldns]:       http://www.nlnetlabs.nl/projects/ldns/
[fstrm]:      https://github.com/farsightsec/fstrm
[protobuf-c]: https://github.com/protobuf-c/protobuf-c
[yaml]:       http://www.yaml.org/

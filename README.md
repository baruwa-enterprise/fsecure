# fsecure

Golang Fsecure Client

[![Build Status](https://travis-ci.org/baruwa-enterprise/fsecure.svg?branch=master)](https://travis-ci.org/baruwa-enterprise/fsecure)
[![Go Report Card](https://goreportcard.com/badge/github.com/baruwa-enterprise/fsecure)](https://goreportcard.com/report/github.com/baruwa-enterprise/fsecure)
[![GoDoc](https://godoc.org/github.com/baruwa-enterprise/fsecure?status.svg)](https://godoc.org/github.com/baruwa-enterprise/fsecure)
[![MPLv2 License](https://img.shields.io/badge/license-MPLv2-blue.svg?style=flat-square)](https://www.mozilla.org/MPL/2.0/)

## Description

fsecure is a Golang library and cmdline tool that implements the
Fsecure client protocol.

## Requirements

* Golang 1.10.x or higher

## Getting started

### Fsecure client

The fsecure client can be installed as follows

```console
$ go get github.com/baruwa-enterprise/fsecure/cmd/fsecurescan
```

Or by cloning the repo and then running

```console
$ make build
$ ./bin/fsecurescan
```

### Fsecure library

To install the library

```console
go get github.com/baruwa-enterprise/fsecure
```

You can then import it in your code

```golang
import "github.com/baruwa-enterprise/fsecure"
```

### Testing

``make test``

## License

MPL-2.0

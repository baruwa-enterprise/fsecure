// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package main Golang F-Secure client Library example program
Fsecure - Golang F-Secure client Library example program
*/
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"sync"
	"time"

	"github.com/baruwa-enterprise/fsecure"
	flag "github.com/spf13/pflag"
)

var (
	address string
	cmdName string
)

func init() {
	cmdName = path.Base(os.Args[0])
	flag.StringVarP(&address, "address", "S", "/Users/andrew/fsav.sock",
		`Specify Fsav unix socket to connect to.`)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", cmdName)
	fmt.Fprint(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
}

func scan(c *fsecure.Client, w *sync.WaitGroup, f string) {
	defer func() {
		w.Done()
	}()

	rt, e := c.Scan(f)
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	fmt.Printf("Scan:\t\t%s\naname\t\t=>\t%s\nstatus\t\t=>\t%s\nsignature\t\t=>\t%s\ninfected\t\t=>\t%t\n",
		rt.Filename, rt.ArchiveItem, rt.Status, rt.Signature, rt.Infected)
	// fmt.Println("RAW=>", rt.Raw)
}

func scanm(c *fsecure.Client, f string) {
	rt, e := c.Scan(f)
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	fmt.Printf("Scan:\t\t%s\naname\t\t=>\t%s\nstatus\t\t=>\t%s\nsignature\t\t=>\t%s\ninfected\t\t=>\t%t\n",
		rt.Filename, rt.ArchiveItem, rt.Status, rt.Signature, rt.Infected)
	// fmt.Println("RAW=>", rt.Raw)
}

func main() {
	// var s string
	files := []string{
		"/var/spool/testfiles/eicar.tar.bz2",
		"/var/spool/testfiles/1fiU7D-00015D-74.eml",
	}
	flag.Usage = usage
	flag.ErrHelp = errors.New("")
	flag.CommandLine.SortFlags = false
	flag.Parse()
	c, e := fsecure.NewClient(address, 5*time.Second, 30*time.Second)
	if e != nil {
		log.Fatalln(e)
		return
	}
	defer c.Close()
	var wg sync.WaitGroup
	for _, fn := range files {
		wg.Add(1)
		go scan(c, &wg, fn)
	}
	wg.Wait()
	// Run in main goroutine
	scanm(c, files[1])
	fmt.Println("Done")
}

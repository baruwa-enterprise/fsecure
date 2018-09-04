// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package fsecure Golang F-Secure client Library
Fsecure - Golang F-Secure client Library
*/
package fsecure

import (
	"fmt"
	"os"
	"testing"
	"time"
)

const (
	localSock = "/Users/andrew/fsav.sock"
)

func TestBasics(t *testing.T) {
	address := os.Getenv("FSECURE_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned: %s", e)
		}
		defer c.Close()
		if c.address != address {
			t.Errorf("Got %q want %q", c.address, address)
		}
		if _, e = NewClient("fe80::879:d85f:f836:1b56%en1", 5*time.Second, 10*time.Second); e == nil {
			t.Fatalf("An error should be returned")
		}
		expect := fmt.Sprintf(unixSockErr, "fe80::879:d85f:f836:1b56%en1")
		if e.Error() != expect {
			t.Errorf("Got %q want %q", e, expect)
		}
	} else {
		t.Skip("skipping test; $FSECURE_ADDRESS not set")
	}
}

func TestConnTimeOut(t *testing.T) {
	address := os.Getenv("FSECURE_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		if c.connTimeout != 5*time.Second {
			t.Errorf("The default conn timeout should be set")
		}
	} else {
		t.Skip("skipping test; $FSECURE_ADDRESS not set")
	}
}

func TestConnSleep(t *testing.T) {
	address := os.Getenv("FSECURE_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		if c.connSleep != defaultSleep {
			t.Errorf("The default conn sleep should be set")
		}
		expected := 2 * time.Second
		c.SetConnSleep(expected)
		if c.connSleep != expected {
			t.Errorf("Calling c.SetConnSleep(%q) failed", expected)
		}
	} else {
		t.Skip("skipping test; $FSECURE_ADDRESS not set")
	}
}

func TestCmdTimeOut(t *testing.T) {
	address := os.Getenv("FSECURE_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		if c.cmdTimeout != 10*time.Second {
			t.Errorf("Expected %q got %q", 10*time.Second, c.cmdTimeout)
		}
		expected := 2 * time.Second
		c.SetCmdTimeout(expected)
		if c.cmdTimeout != expected {
			t.Errorf("Calling c.SetCmdTimeout(%q) failed", expected)
		}
	} else {
		t.Skip("skipping test; $FSECURE_ADDRESS not set")
	}
}

func TestConnRetries(t *testing.T) {
	address := os.Getenv("FSECURE_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		if c.connRetries != 0 {
			t.Errorf("The default conn retries should be set")
		}
		c.SetConnRetries(2)
		if c.connRetries != 2 {
			t.Errorf("Calling c.SetConnRetries(%q) failed", 2)
		}
		c.SetConnRetries(-2)
		if c.connRetries != 0 {
			t.Errorf("Preventing negative values in c.SetConnRetries(%q) failed", -2)
		}
	} else {
		t.Skip("skipping test; $FSECURE_ADDRESS not set")
	}
}

func TestBasicError(t *testing.T) {
	if _, e := os.Stat(FsavSock); os.IsNotExist(e) {
		_, e := NewClient("", 5*time.Second, 10*time.Second)
		if e == nil {
			t.Fatalf("An error should be returned")
		}
		expected := fmt.Sprintf(unixSockErr, FsavSock)
		if e.Error() != expected {
			t.Errorf("Got %q want %q", e, expected)
		}
	} else {
		t.Skip("skipping test; /tmp/.fsav-0 exists")
	}
}

func TestScan(t *testing.T) {
	address := os.Getenv("FSECURE_ADDRESS")
	if address == "" {
		address = localSock
	}

	if _, e := os.Stat(address); !os.IsNotExist(e) {
		c, e := NewClient(address, 5*time.Second, 10*time.Second)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		defer c.Close()
		fn := "/var/spool/testfiles/eicar.tar.bz2"
		r, e := c.Scan(fn)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if r.Filename != fn {
			t.Errorf("r.Filename = %q, want %q", r.Filename, fn)
		}
		if r.ArchiveItem != "" {
			t.Errorf("r.ArchiveItem = %q, want %q", r.ArchiveItem, "")
		}
		sig := "EICAR-Test-File (not a virus)"
		if r.Signature != sig {
			t.Errorf("r.Signature = %q, want %q", r.Signature, sig)
		}
		sts := "MIME_INFECTED"
		if r.Status != sts {
			t.Errorf("r.Status = %q, want %q", r.Status, sts)
		}
		if !r.Infected {
			t.Errorf("r.Infected = %t, want %t", r.Infected, true)
		}
		fn = "/var/spool/testfiles/1fiU7D-00015D-74.eml"
		r, e = c.Scan(fn)
		if e != nil {
			t.Fatalf("An error should not be returned")
		}
		if r.Filename != fn {
			t.Errorf("r.Filename = %q, want %q", r.Filename, fn)
		}
		an := "[1] SWIFTMT103.exe"
		if r.ArchiveItem != an {
			t.Errorf("r.ArchiveItem = %q, want %q", r.ArchiveItem, an)
		}
		sig = "Trojan.GenericKD.40336677"
		if r.Signature != sig {
			t.Errorf("r.Signature = %q, want %q", r.Signature, sig)
		}
		sts = "ARCHIVE_INFECTED"
		if r.Status != sts {
			t.Errorf("r.Status = %q, want %q", r.Status, sts)
		}
		if !r.Infected {
			t.Errorf("r.Infected = %t, want %t", r.Infected, true)
		}
	} else {
		t.Skip("skipping test; $FSECURE_ADDRESS not set")
	}
}

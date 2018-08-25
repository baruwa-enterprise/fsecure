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
	"net"
	"net/textproto"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// FsavSock is the default socket location
	FsavSock          = "/tmp/.fsav-0"
	defaultTimeout    = 15 * time.Second
	defaultSleep      = 1 * time.Second
	defaultCmdTimeout = 1 * time.Minute
	protocolVersion   = 9
)

var (
	// ZeroTime holds the zero value of time
	ZeroTime   time.Time
	responseRe = regexp.MustCompile(`^(?P<sc>\S*?_?(?:INFECTED|SUSPECTED))\t(?P<fn>[^\t]+)\t(?P<sig>[^\t]+)\t(?:[^\t]+)\t\d+\t\d+\t\d+\t\d+$`)
)

// Response is the response from the server
type Response struct {
	Filename    string
	ArchiveItem string
	Signature   string
	Status      string
	Infected    bool
	Raw         string
}

// A Client represents a Fsecure client.
type Client struct {
	address     string
	connTimeout time.Duration
	connRetries int
	connSleep   time.Duration
	cmdTimeout  time.Duration
	tc          *textproto.Conn
	m           sync.Mutex
	conn        net.Conn
	// Config holds the fsav config options
	Config *Config
}

// SetCmdTimeout sets the cmd timeout
func (c *Client) SetCmdTimeout(t time.Duration) {
	c.cmdTimeout = t
}

// SetConnRetries sets the number of times
// connection is retried
func (c *Client) SetConnRetries(s int) {
	if s < 0 {
		s = 0
	}
	c.connRetries = s
}

// SetConnSleep sets the connection retry sleep
// duration in seconds
func (c *Client) SetConnSleep(s time.Duration) {
	c.connSleep = s
}

// SetOptions sets the fsav config options on the server
func (c *Client) SetOptions() (err error) {
	elm := reflect.ValueOf(c.Config).Elem()
	for i := 0; i < elm.NumField(); i++ {
		n := strings.ToUpper(elm.Type().Field(i).Name)
		v := elm.Field(i).Interface()
		if err = c.sendOpt(n, v); err != nil {
			break
		}
	}
	return
}

// Close closes the server connection
func (c *Client) Close() {
	c.tc.Close()

	return
}

// Scan a file
func (c *Client) Scan(p string) (r *Response, err error) {
	r, err = c.fileCmd(p)
	return
}

func (c *Client) fileCmd(p string) (r *Response, err error) {
	var id uint
	var line string

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	id = c.tc.Next()
	c.tc.StartRequest(id)

	if _, err = fmt.Fprintf(c.tc.W, "SCAN\t%s\n", p); err != nil {
		c.tc.EndRequest(id)
		return
	}

	if err = c.tc.W.Flush(); err != nil {
		c.tc.EndRequest(id)
		return
	}

	c.tc.EndRequest(id)
	c.tc.StartResponse(id)
	defer c.tc.EndResponse(id)

	r = &Response{
		Filename: p,
	}

	for {
		c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
		if line, err = c.tc.ReadLine(); err != nil {
			return
		}

		if strings.HasPrefix(line, "OK") {
			break
		}

		m := responseRe.FindStringSubmatch(line)
		if m != nil {
			r.Infected = true
			r.Raw = line
			r.Status = m[1]
			if m[2] != p {
				r.ArchiveItem = m[2]
			}
			r.Signature = m[3]
			continue
		}
	}

	return
}

func (c *Client) dial() (conn net.Conn, err error) {
	d := &net.Dialer{
		Timeout: c.connTimeout,
	}

	for i := 0; i <= c.connRetries; i++ {
		conn, err = d.Dial("unix", c.address)
		if e, ok := err.(net.Error); ok && e.Timeout() {
			time.Sleep(c.connSleep)
			continue
		}
		break
	}
	return
}

func (c *Client) sendOpt(n string, v interface{}) (err error) {
	var id uint
	var line string

	id = c.tc.Next()
	c.tc.StartRequest(id)
	defer c.conn.SetDeadline(ZeroTime)

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if _, err = fmt.Fprintf(c.tc.W, "CONFIGURE\t%s\t%s\n", n, v); err != nil {
		c.tc.EndRequest(id)
		return
	}

	if err = c.tc.W.Flush(); err != nil {
		c.tc.EndRequest(id)
		return
	}
	c.tc.EndRequest(id)
	c.tc.StartResponse(id)
	defer c.tc.EndResponse(id)

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	if line, err = c.tc.ReadLine(); err != nil {
		return
	}

	if !strings.HasPrefix(line, "OK") {
		err = fmt.Errorf("Set option: %s failed: %s", n, line)
		return
	}

	return
}

// NewClient creates and returns a new instance of Client
func NewClient(address string, connTimeOut, ioTimeOut time.Duration) (c *Client, err error) {
	var line string
	if address == "" {
		address = FsavSock
	}

	if _, err = os.Stat(address); os.IsNotExist(err) {
		err = fmt.Errorf("The unix socket: %s does not exist", address)
		return
	}

	c = &Client{
		address:     address,
		connTimeout: connTimeOut,
		connSleep:   defaultSleep,
		cmdTimeout:  ioTimeOut,
		Config:      NewConfig(),
	}

	c.m.Lock()
	defer c.m.Unlock()

	if c.conn, err = c.dial(); err != nil {
		return
	}

	c.conn.SetDeadline(time.Now().Add(c.cmdTimeout))
	defer c.conn.SetDeadline(ZeroTime)

	c.tc = textproto.NewConn(c.conn)

	if line, err = c.tc.ReadLine(); err != nil {
		return
	}

	if !strings.HasPrefix(line, "DBVERSION") {
		err = fmt.Errorf("Greeting failed: %s", line)
		c.tc.Close()
		return
	}

	if _, err = fmt.Fprintf(c.tc.W, "PROTOCOL\t%d\n", protocolVersion); err != nil {
		c.tc.Close()
		return
	}

	if err = c.tc.W.Flush(); err != nil {
		c.tc.Close()
		return
	}

	if line, err = c.tc.ReadLine(); err != nil {
		return
	}

	if !strings.HasPrefix(line, "OK") {
		err = fmt.Errorf("Protocol negotiation failed: %s", line)
		c.tc.Close()
		return
	}

	if err = c.SetOptions(); err != nil {
		c.tc.Close()
		return
	}

	return
}

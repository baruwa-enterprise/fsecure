// Copyright (C) 2018-2021 Andrew Colin Kissa <andrew@datopdog.io>
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
)

// Config holds Fsecure fsav options
type Config struct {
	Mime        BoolField
	RiskWare    BoolField
	StopOnFirst BoolField
	Timeout     IntField
	Archive     BoolField
}

// BoolField local adaptation of bool
type BoolField bool

func (b BoolField) String() (s string) {
	s = "0"
	if b {
		s = "1"
	}

	return
}

// IntField local adaptation of int
type IntField int

func (i IntField) String() (s string) {
	s = fmt.Sprintf("%d", i)

	return
}

// NewConfig returns a new config object
func NewConfig() (c *Config) {
	c = &Config{
		Mime:        true,
		RiskWare:    true,
		StopOnFirst: true,
		Timeout:     60,
		Archive:     true,
	}
	return
}

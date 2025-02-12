// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bice

import (
	"testing"

	"github.com/leonhwangprojects/bice/internal/test"
)

var isBigEndian = ne.Uint16([]byte{0x12, 0x34}) == 0x1234

func TestEndian(t *testing.T) {
	tests := []struct {
		name string
		n    uint64
		be   uint64
		fn   func(t *testing.T, n, exp uint64)
	}{
		{
			name: "h2ns",
			n:    0x1234,
			be:   0x3412,
			fn: func(t *testing.T, n, exp uint64) {
				test.AssertEqual(t, h2ns(uint16(n)), uint16(exp))
			},
		},
		{
			name: "h2nl",
			n:    0x12345678,
			be:   0x78563412,
			fn: func(t *testing.T, n, exp uint64) {
				test.AssertEqual(t, h2nl(uint32(n)), uint32(exp))
			},
		},
		{
			name: "h2nll",
			n:    0x1234567890abcdef,
			be:   0xefcdab9078563412,
			fn: func(t *testing.T, n, exp uint64) {
				test.AssertEqual(t, h2nll(n), exp)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isBigEndian {
				tt.fn(t, tt.n, tt.n)
			} else {
				tt.fn(t, tt.n, tt.be)
			}
		})
	}
}

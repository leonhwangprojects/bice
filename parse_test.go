// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bice

import (
	"testing"

	"github.com/leonhwangprojects/bice/internal/test"
)

func TestParseNumber(t *testing.T) {
	tests := []struct {
		name string
		text string
		exp  uint64
	}{
		{
			name: "hex",
			text: "0x1234",
			exp:  0x1234,
		},
		{
			name: "oct",
			text: "0o1234",
			exp:  0o1234,
		},
		{
			name: "bin",
			text: "0b1010",
			exp:  0b1010,
		},
		{
			name: "dec",
			text: "1234",
			exp:  1234,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNumber(tt.text)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, got, tt.exp)
		})
	}
}

// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bice

import (
	"testing"

	"github.com/leonhwangprojects/bice/internal/test"
)

func TestSimpleCompile(t *testing.T) {
	t.Run("failed to parse", func(t *testing.T) {
		_, err := SimpleCompile("a)(test)", nil)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to parse expression")
	})

	t.Run("failed to validate", func(t *testing.T) {
		_, err := SimpleCompile("skb->xxx", getSkbBtf(t))
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to validate expression")
	})

	t.Run("failed to compile", func(t *testing.T) {
		_, err := SimpleCompile("skb->dev->ifindexx == 9", getSkbBtf(t))
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to compile expression")
	})

	t.Run("success", func(t *testing.T) {
		insns, err := SimpleCompile("skb->len > 1024", getSkbBtf(t))
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, insns, skbLen1024Insns)
	})
}

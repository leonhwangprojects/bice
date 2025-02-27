// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package bice

import (
	"testing"

	"github.com/leonhwangprojects/bice/internal/test"
)

func TestAccess(t *testing.T) {
	t.Run("empty options", func(t *testing.T) {
		_, _, err := Access(AccessOptions{})
		test.AssertHaveErr(t, err)
		test.AssertEqual(t, err.Error(), "invalid options")
	})
}

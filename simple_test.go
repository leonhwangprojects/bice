// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bice

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

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

	t.Run("(struct sk_buff *)skb->len > 1024", func(t *testing.T) {
		insns, err := SimpleCompile("skb->len > 1024", getSkbBtf(t))
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, insns, cloneSkbLen1024InsnsWithoutExitLabel())
	})

	t.Run("(u64)skb != 0", func(t *testing.T) {
		insns, err := SimpleCompile("skb != 0", getU64Btf(t))
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, insns, asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R1),
			asm.Mov.Imm(asm.R0, 1),
			asm.JNE.Imm(asm.R3, 0, labelReturn),
			asm.Xor.Reg(asm.R0, asm.R0),
			asm.Return().WithSymbol(labelReturn),
		})
	})
}

func TestSimpleInjectFilter(t *testing.T) {
	t.Run("empty options", func(t *testing.T) {
		err := SimpleInjectFilter(InjectOptions{})
		test.AssertNoErr(t, err)
	})

	t.Run("failed to SimpleCompile", func(t *testing.T) {
		err := SimpleInjectFilter(InjectOptions{
			Prog:     &ebpf.ProgramSpec{},
			StubFunc: "__stub",
			Expr:     "a)(test)",
			Type:     getSkbBtf(t),
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to parse expression")
	})

	t.Run("inject", func(t *testing.T) {
		prog := prepareProgSpec()
		insns := cloneSkbLen1024InsnsWithoutExitLabel()
		insns[0] = insns[0].WithMetadata(prog.Instructions[4].Metadata)

		err := SimpleInjectFilter(InjectOptions{
			Prog:     prog,
			StubFunc: "__stub",
			Expr:     "skb->len > 1024",
			Type:     getSkbBtf(t),
		})
		test.AssertNoErr(t, err)

		test.AssertEqualSlice(t, prog.Instructions[4:], insns)
	})
}

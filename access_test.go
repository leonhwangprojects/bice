// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package bice

import (
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/leonhwangprojects/bice/internal/test"
)

func TestAccess(t *testing.T) {
	t.Run("empty options", func(t *testing.T) {
		_, err := Access(AccessOptions{})
		test.AssertHaveErr(t, err)
		test.AssertEqual(t, err.Error(), "invalid options")
	})

	t.Run("failed to parse", func(t *testing.T) {
		_, err := Access(AccessOptions{
			Expr:      "a)(test)",
			Type:      getSkbBtf(t),
			LabelExit: labelExitFail,
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to compile expression")
	})

	t.Run("invalid left operand", func(t *testing.T) {
		_, err := Access(AccessOptions{
			Expr:      "a+b == c",
			Type:      getSkbBtf(t),
			LabelExit: labelExitFail,
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "expression is not struct/union member access")
	})

	t.Run("failed to convert expression to offsets", func(t *testing.T) {
		_, err := Access(AccessOptions{
			Expr:      "skb->xxx",
			Type:      getSkbBtf(t),
			LabelExit: labelExitFail,
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to convert expression to offsets")
	})

	t.Run("empty offsets", func(t *testing.T) {
		_, err := Access(AccessOptions{
			Expr:      "skb",
			Type:      getSkbBtf(t),
			LabelExit: labelExitFail,
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "expr should be struct/union member access")
	})

	t.Run("failed to check last field", func(t *testing.T) {
		_, err := Access(AccessOptions{
			Expr:      "skb->users",
			Type:      getSkbBtf(t),
			LabelExit: labelExitFail,
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "unexpected type of last field")
	})

	t.Run("skb->dev->name", func(t *testing.T) {
		insns, err := Access(AccessOptions{
			Expr:      "skb->dev->name",
			Type:      getSkbBtf(t),
			Src:       asm.R1,
			Dst:       asm.R3,
			Insns:     nil,
			LabelExit: labelExitFail,
		})
		test.AssertNoErr(t, err)
		test.AssertTrue(t, insns.LabelUsed)
		test.AssertEqualSlice(t, insns.Insns, asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R1),
			asm.Add.Imm(asm.R3, 16),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.R10),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord),
			asm.JEq.Imm(asm.R3, 0, labelExitFail),
			asm.Add.Imm(asm.R3, 304),
		})
	})

	t.Run("kobj->name", func(t *testing.T) {
		insns, err := Access(AccessOptions{
			Expr:      "kobj->name",
			Type:      getKobjBtf(t),
			Src:       asm.R1,
			Dst:       asm.R3,
			Insns:     nil,
			LabelExit: labelExitFail,
		})
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, insns.Insns, asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R1),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.R10),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord),
		})
	})

	t.Run("skb->len", func(t *testing.T) {
		insns, err := Access(AccessOptions{
			Expr:      "skb->len",
			Type:      getSkbBtf(t),
			Src:       asm.R1,
			Dst:       asm.R3,
			Insns:     nil,
			LabelExit: labelExitFail,
		})
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, insns.Insns, asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R1),
			asm.Add.Imm(asm.R3, 112),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.R10),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord),
			asm.LSh.Imm(asm.R3, 32),
			asm.RSh.Imm(asm.R3, 32),
		})
		test.AssertEqual(t, insns.LabelUsed, false)
	})

	t.Run("skb->pkt_type", func(t *testing.T) {
		res, err := Access(AccessOptions{
			Expr:      "skb->pkt_type",
			Type:      getSkbBtf(t),
			Src:       asm.R3,
			Dst:       asm.R3,
			Insns:     nil,
			LabelExit: labelExitFail,
		})
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, res.Insns, asm.Instructions{
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.R10),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord),
			asm.And.Imm(asm.R3, 0x7),
		})
	})

	t.Run("skb->pkt_type and src r1 and dst r2", func(t *testing.T) {
		res, err := Access(AccessOptions{
			Expr:      "skb->pkt_type",
			Type:      getSkbBtf(t),
			Src:       asm.R1,
			Dst:       asm.R2,
			Insns:     nil,
			LabelExit: labelExitFail,
		})
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, res.Insns, asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R1),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.R10),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R2, asm.RFP, -8, asm.DWord),
			asm.And.Imm(asm.R2, 0x7),
		})
	})
}

// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bice

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/leonhwangprojects/bice/internal/test"
)

func prepareProgSpec() *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.Instruction{
				OpCode:   asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call),
				Src:      asm.PseudoCall,
				Dst:      asm.R0,
				Constant: -1,
			}.WithReference("__stub"),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
			asm.Mov.Imm(asm.R0, 1).WithSymbol("__stub"),
			asm.Return(),
		},
	}
}

func TestFindStubFunc(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		prog := prepareProgSpec()
		idx, found := findStubFunc(prog, "__stub")
		test.AssertTrue(t, found)
		test.AssertEqual(t, idx, 4)
	})

	t.Run("not found", func(t *testing.T) {
		prog := prepareProgSpec()
		idx, found := findStubFunc(prog, "__not_found")
		test.AssertFalse(t, found)
		test.AssertEqual(t, idx, -1)
	})
}

func TestFindRetInsn(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		prog := prepareProgSpec()
		idx, found := findRetInsn(prog, 4)
		test.AssertTrue(t, found)
		test.AssertEqual(t, idx, 5)
	})

	t.Run("not found", func(t *testing.T) {
		prog := prepareProgSpec().Copy()
		prog.Instructions[len(prog.Instructions)-1] = asm.FnProbeReadKernel.Call()
		idx, found := findRetInsn(prog, 4)
		test.AssertFalse(t, found)
		test.AssertEqual(t, idx, -1)
	})
}

func TestInject(t *testing.T) {
	t.Run("not find stub func", func(t *testing.T) {
		prog := prepareProgSpec()
		opts := InjectOptions{
			Prog:     prog,
			StubFunc: "__not_found",
			Expr:     "skb->dev->ifindex == 1",
		}
		err := inject(opts, asm.Instructions{})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "cannot find the stub function(__not_found)")
	})

	t.Run("not find return insn", func(t *testing.T) {
		prog := prepareProgSpec()
		prog.Instructions = prog.Instructions[:len(prog.Instructions)-1]
		opts := InjectOptions{
			Prog:     prog,
			StubFunc: "__stub",
			Expr:     "skb->dev->ifindex == 1",
		}
		err := inject(opts, asm.Instructions{})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "cannot find the return insn of the stub function(__stub)")
	})

	t.Run("inject", func(t *testing.T) {
		prog := prepareProgSpec()
		opts := InjectOptions{
			Prog:     prog,
			StubFunc: "__stub",
			Expr:     "skb->dev->ifindex == 1",
		}
		err := inject(opts, asm.Instructions{
			asm.Mov.Imm(asm.R0, 2),
			asm.Return(),
		})
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, prog.Instructions, asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.Instruction{
				OpCode:   asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call),
				Src:      asm.PseudoCall,
				Dst:      asm.R0,
				Constant: -1,
			}.WithReference("__stub"),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
			asm.Mov.Imm(asm.R0, 2).WithSymbol("__stub"),
			asm.Return(),
		})
	})
}

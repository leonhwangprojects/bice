// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bice

import (
	"bytes"
	_ "embed"
	"log"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/leonhwangprojects/bice/internal/test"
	"rsc.io/c2go/cc"
)

//go:embed testdata/vmlinux_v680_btf.o
var btfFile []byte

var testBtf *btf.Spec

func init() {
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(btfFile))
	if err != nil {
		log.Fatalf("Failed to load btf spec: %v", err)
	}

	testBtf = spec
}

func getSkbBtf(t *testing.T) *btf.Pointer {
	skb, err := testBtf.AnyTypeByName("sk_buff")
	test.AssertNoErr(t, err)
	return &btf.Pointer{Target: skb}
}

func TestIsMemberBitfield(t *testing.T) {
	test.AssertFalse(t, isMemberBitfield(nil))
	test.AssertTrue(t, isMemberBitfield(&btf.Member{Offset: 1, BitfieldSize: 1}))
	test.AssertFalse(t, isMemberBitfield(&btf.Member{Offset: 8, BitfieldSize: 8}))
}

func TestExpr2offset(t *testing.T) {
	t.Run("empty expr", func(t *testing.T) {
		_, err := expr2offset(&cc.Expr{}, nil)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb != 0", func(t *testing.T) {
		expr, err := parse("skb != 0")
		test.AssertNoErr(t, err)

		skb := getSkbBtf(t)

		ast, err := expr2offset(expr, skb)
		test.AssertNoErr(t, err)
		test.AssertEmptySlice(t, ast.offsets)
		test.AssertTrue(t, ast.lastField == skb)
		test.AssertFalse(t, ast.bigEndian)
	})

	t.Run("skb->len > 1024", func(t *testing.T) {
		expr, err := parse("skb->len > 1024")
		test.AssertNoErr(t, err)

		skb := getSkbBtf(t)
		uint, err := testBtf.AnyTypeByName("unsigned int")
		test.AssertNoErr(t, err)

		ast, err := expr2offset(expr, skb)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, ast.offsets, []uint32{112})
		test.AssertTrue(t, ast.lastField == uint)
		test.AssertFalse(t, ast.bigEndian)
	})

	t.Run("skb->vlan_tci == 1000", func(t *testing.T) {
		expr, err := parse("skb->vlan_tci == 1000")
		test.AssertNoErr(t, err)

		skb := getSkbBtf(t)
		vlanTci, err := testBtf.AnyTypeByName("short unsigned int")
		test.AssertNoErr(t, err)

		ast, err := expr2offset(expr, skb)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, ast.offsets, []uint32{158})
		test.AssertTrue(t, ast.lastField == vlanTci)
		test.AssertFalse(t, ast.bigEndian)
	})

	t.Run("skb->protocol == 0x0008", func(t *testing.T) {
		expr, err := parse("skb->protocol == 0x0008")
		test.AssertNoErr(t, err)

		skb := getSkbBtf(t)
		protocol, err := testBtf.AnyTypeByName("short unsigned int")
		test.AssertNoErr(t, err)

		ast, err := expr2offset(expr, skb)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, ast.offsets, []uint32{180})
		test.AssertTrue(t, ast.lastField == protocol)
		test.AssertTrue(t, ast.bigEndian)
	})

	t.Run("skb->dev->ifindex == 1", func(t *testing.T) {
		expr, err := parse("skb->dev->ifindex == 1")
		test.AssertNoErr(t, err)

		skb := getSkbBtf(t)
		ifindex, err := testBtf.AnyTypeByName("int")
		test.AssertNoErr(t, err)

		ast, err := expr2offset(expr, skb)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, ast.offsets, []uint32{16, 224})
		test.AssertTrue(t, ast.lastField == ifindex)
		test.AssertFalse(t, ast.bigEndian)
	})

	t.Run("skb->dev->nd_net.net->ns.inum == 0xffffedcba987", func(t *testing.T) {
		expr, err := parse("skb->dev->nd_net.net->ns.inum == 0xffffedcba987")
		test.AssertNoErr(t, err)

		skb := getSkbBtf(t)
		uint, err := testBtf.AnyTypeByName("unsigned int")
		test.AssertNoErr(t, err)

		ast, err := expr2offset(expr, skb)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, ast.offsets, []uint32{16, 280, 136})
		test.AssertTrue(t, ast.lastField == uint)
		test.AssertFalse(t, ast.bigEndian)
	})

	t.Run("unexpected skb->xxx", func(t *testing.T) {
		expr, err := parse("skb->xxx == 0")
		test.AssertNoErr(t, err)

		skb := getSkbBtf(t)

		_, err = expr2offset(expr, skb)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to find member xxx of sk_buff")
	})
}

type offsetinsns struct {
	offsets []uint32
	insns   asm.Instructions
}

var testOffsetsInsnsCases = []offsetinsns{
	{
		offsets: []uint32{0},
		insns: asm.Instructions{
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.R10),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.R10, -8, asm.DWord),
		},
	},
	{
		offsets: []uint32{1},
		insns: asm.Instructions{
			asm.Add.Imm(asm.R3, 1),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.R10),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.R10, -8, asm.DWord),
		},
	},
	{
		offsets: []uint32{0, 1, 2},
		insns: asm.Instructions{
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.R10),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.R10, -8, asm.DWord),
			asm.JEq.Imm(asm.R3, 0, labelExitFail),

			asm.Add.Imm(asm.R3, 1),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.R10),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.R10, -8, asm.DWord),
			asm.JEq.Imm(asm.R3, 0, labelExitFail),

			asm.Add.Imm(asm.R3, 2),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.R10),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.R10, -8, asm.DWord),
		},
	},
}

func TestOffset2insns(t *testing.T) {
	t.Run("empty offset", func(t *testing.T) {
		insns := offset2insns(nil, nil)
		test.AssertEmptySlice(t, insns)
	})

	t.Run("offsets = [0]", func(t *testing.T) {
		cas := testOffsetsInsnsCases[0]
		insns := offset2insns(nil, cas.offsets)
		test.AssertEqualSlice(t, insns, cas.insns)
	})

	t.Run("offsets = [1]", func(t *testing.T) {
		cas := testOffsetsInsnsCases[1]
		insns := offset2insns(nil, cas.offsets)
		test.AssertEqualSlice(t, insns, cas.insns)
	})

	t.Run("offsets = [0, 1, 2]", func(t *testing.T) {
		cas := testOffsetsInsnsCases[2]
		insns := offset2insns(nil, cas.offsets)
		test.AssertEqualSlice(t, insns, cas.insns)
	})
}

func TestTgt2insns(t *testing.T) {
	tests := []struct {
		name     string
		tgt      tgtInfo
		expConst uint64
		expInsns asm.Instructions
	}{
		{
			name: "u8",
			tgt: tgtInfo{
				sizof:    1,
				constant: 0x12345678,
			},
			expConst: 0x78,
			expInsns: asm.Instructions{
				asm.And.Imm(asm.R3, 0xFF),
			},
		},
		{
			name: "u16",
			tgt: tgtInfo{
				sizof:    2,
				constant: 0x12345678,
			},
			expConst: 0x5678,
			expInsns: asm.Instructions{
				asm.And.Imm(asm.R3, 0xFFFF),
			},
		},
		{
			name: "be16",
			tgt: tgtInfo{
				sizof:     2,
				constant:  0x12345678,
				bigEndian: true,
			},
			expConst: 0x7856,
			expInsns: asm.Instructions{
				asm.And.Imm(asm.R3, 0xFFFF),
			},
		},
		{
			name: "u32",
			tgt: tgtInfo{
				sizof:    4,
				constant: 0x12345678,
			},
			expConst: 0x12345678,
			expInsns: asm.Instructions{
				asm.LSh.Imm(asm.R3, 32),
				asm.RSh.Imm(asm.R3, 32),
			},
		},
		{
			name: "be32",
			tgt: tgtInfo{
				sizof:     4,
				constant:  0x12345678,
				bigEndian: true,
			},
			expConst: 0x78563412,
			expInsns: asm.Instructions{
				asm.LSh.Imm(asm.R3, 32),
				asm.RSh.Imm(asm.R3, 32),
			},
		},
		{
			name: "u64",
			tgt: tgtInfo{
				sizof:    8,
				constant: 0x123456789abcdef0,
			},
			expConst: 0x123456789abcdef0,
			expInsns: nil,
		},
		{
			name: "be64",
			tgt: tgtInfo{
				sizof:     8,
				constant:  0x123456789abcdef0,
				bigEndian: true,
			},
			expConst: 0xf0debc9a78563412,
			expInsns: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insns, constant := tgt2insns(nil, tt.tgt)
			test.AssertEqualSlice(t, insns, tt.expInsns)
			test.AssertEqual(t, constant, tt.expConst)
		})
	}
}

func TestOp2insns(t *testing.T) {
	const tgtConst = 0x12345678

	tests := []struct {
		name     string
		op       cc.ExprOp
		tgt      tgtInfo
		expInsns asm.Instructions
	}{
		{
			name: "eq",
			op:   cc.Eq,
			tgt: tgtInfo{
				typ:      &btf.Int{Encoding: btf.Unsigned},
				constant: tgtConst,
			},
			expInsns: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.JEq.Imm(asm.R3, tgtConst, labelReturn),
			},
		},
		{
			name: "eqeq",
			op:   cc.EqEq,
			tgt: tgtInfo{
				typ:      &btf.Int{Encoding: btf.Unsigned},
				constant: tgtConst,
			},
			expInsns: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.JEq.Imm(asm.R3, tgtConst, labelReturn),
			},
		},
		{
			name: "noteq",
			op:   cc.NotEq,
			tgt: tgtInfo{
				typ:      &btf.Int{Encoding: btf.Unsigned},
				constant: tgtConst,
			},
			expInsns: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.JNE.Imm(asm.R3, tgtConst, labelReturn),
			},
		},
		{
			name: "lt unsigned",
			op:   cc.Lt,
			tgt: tgtInfo{
				typ:      &btf.Int{Encoding: btf.Unsigned},
				constant: tgtConst,
			},
			expInsns: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.JLT.Imm(asm.R3, tgtConst, labelReturn),
			},
		},
		{
			name: "lt signed",
			op:   cc.Lt,
			tgt: tgtInfo{
				typ:      &btf.Int{Encoding: btf.Signed},
				constant: tgtConst,
			},
			expInsns: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.JSLT.Imm(asm.R3, tgtConst, labelReturn),
			},
		},
		{
			name: "lte unsigned",
			op:   cc.LtEq,
			tgt: tgtInfo{
				typ:      &btf.Int{Encoding: btf.Unsigned},
				constant: tgtConst,
			},
			expInsns: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.JLE.Imm(asm.R3, tgtConst, labelReturn),
			},
		},
		{
			name: "lte signed",
			op:   cc.LtEq,
			tgt: tgtInfo{
				typ:      &btf.Int{Encoding: btf.Signed},
				constant: tgtConst,
			},
			expInsns: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.JSLE.Imm(asm.R3, tgtConst, labelReturn),
			},
		},
		{
			name: "gt unsigned",
			op:   cc.Gt,
			tgt: tgtInfo{
				typ:      &btf.Int{Encoding: btf.Unsigned},
				constant: tgtConst,
			},
			expInsns: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.JGT.Imm(asm.R3, tgtConst, labelReturn),
			},
		},
		{
			name: "gt signed",
			op:   cc.Gt,
			tgt: tgtInfo{
				typ:      &btf.Int{Encoding: btf.Signed},
				constant: tgtConst,
			},
			expInsns: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.JSGT.Imm(asm.R3, tgtConst, labelReturn),
			},
		},
		{
			name: "gte unsigned",
			op:   cc.GtEq,
			tgt: tgtInfo{
				typ:      &btf.Int{Encoding: btf.Unsigned},
				constant: tgtConst,
			},
			expInsns: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.JGE.Imm(asm.R3, tgtConst, labelReturn),
			},
		},
		{
			name: "gte signed",
			op:   cc.GtEq,
			tgt: tgtInfo{
				typ:      &btf.Int{Encoding: btf.Signed},
				constant: tgtConst,
			},
			expInsns: asm.Instructions{
				asm.Mov.Imm(asm.R0, 1),
				asm.JSGE.Imm(asm.R3, tgtConst, labelReturn),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insns, err := op2insns(nil, tt.op, tt.tgt)
			test.AssertNoErr(t, err)
			test.AssertEqualSlice(t, insns, tt.expInsns)
		})
	}

	t.Run("unexpected operator", func(t *testing.T) {
		_, err := op2insns(nil, cc.ExprOp(0), tgtInfo{
			typ:      &btf.Int{Encoding: btf.Unsigned},
			constant: tgtConst,
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "unexpected operator")
	})
}

func TestCompile(t *testing.T) {
	t.Run("nil expr", func(t *testing.T) {
		_, err := compile(nil, nil)
		test.AssertHaveErr(t, err)

		_, err = compile(&cc.Expr{}, nil)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		expr, err := parse("skb->len > 1024x")
		test.AssertNoErr(t, err)

		_, err = compile(expr, nil)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to parse right operand as number")
	})

	t.Run("failed to expr2offset", func(t *testing.T) {
		expr, err := parse("skb->xxx == 0")
		test.AssertNoErr(t, err)

		_, err = compile(expr, getSkbBtf(t))
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to convert expr to access offsets")
	})

	t.Run("invalid last field type", func(t *testing.T) {
		expr, err := parse("skb->users == 0")
		test.AssertNoErr(t, err)

		_, err = compile(expr, getSkbBtf(t))
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "unexpected type of last field")
	})

	t.Run("unexpected bitfield", func(t *testing.T) {
		expr, err := parse("skb->pkt_type == 0")
		test.AssertNoErr(t, err)

		_, err = compile(expr, getSkbBtf(t))
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "unexpected member access of bitfield")
	})

	t.Run("invalid operator", func(t *testing.T) {
		expr, err := parse("skb->len * 2")
		test.AssertNoErr(t, err)
		test.AssertEqual(t, expr.Op, cc.Mul)

		_, err = compile(expr, getSkbBtf(t))
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to convert operator to instructions")
	})

	t.Run("skb != 0", func(t *testing.T) {
		expr, err := parse("skb != 0")
		test.AssertNoErr(t, err)

		insns, err := compile(expr, getSkbBtf(t))
		test.AssertNoErr(t, err)

		test.AssertEqualSlice(t, insns, asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R1),
			asm.Mov.Imm(asm.R0, 1),
			asm.JNE.Imm(asm.R3, 0, labelReturn),
			asm.Mov.Imm(asm.R0, 0).WithSymbol(labelExitFail),
			asm.Return().WithSymbol(labelReturn),
		})
	})

	t.Run("skb->len > 1024", func(t *testing.T) {
		expr, err := parse("skb->len > 1024")
		test.AssertNoErr(t, err)

		insns, err := compile(expr, getSkbBtf(t))
		test.AssertNoErr(t, err)

		test.AssertEqualSlice(t, insns, skbLen1024Insns)
	})
}

var skbLen1024Insns = asm.Instructions{
	asm.Mov.Reg(asm.R3, asm.R1),
	asm.Add.Imm(asm.R3, 112),
	asm.Mov.Imm(asm.R2, 8),
	asm.Mov.Reg(asm.R1, asm.R10),
	asm.Add.Imm(asm.R1, -8),
	asm.FnProbeReadKernel.Call(),
	asm.LoadMem(asm.R3, asm.R10, -8, asm.DWord),
	asm.LSh.Imm(asm.R3, 32),
	asm.RSh.Imm(asm.R3, 32),
	asm.Mov.Imm(asm.R0, 1),
	asm.JGT.Imm(asm.R3, 1024, labelReturn),
	asm.Mov.Imm(asm.R0, 0).WithSymbol(labelExitFail),
	asm.Return().WithSymbol(labelReturn),
}

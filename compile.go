// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package bice

import (
	"fmt"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

const (
	labelExitFail = "__exit_bice_filter"
	labelReturn   = "__return_bice_filter"
)

func isMemberBitfield(member *btf.Member) bool {
	if member == nil {
		return false
	}

	return member.Offset%8 != 0 || member.BitfieldSize%8 != 0
}

type astInfo struct {
	offsets   []uint32
	member    *btf.Member
	lastField btf.Type
	bigEndian bool // true if the last field is big endian
}

func expr2offset(expr *cc.Expr, typ btf.Type) (astInfo, error) {
	var ast astInfo

	var exprStack []*cc.Expr
	for left := expr.Left; left != nil; left = left.Left {
		exprStack = append(exprStack, left)
	}

	if len(exprStack) == 1 {
		ast.lastField = typ
		ast.bigEndian = mybtf.IsBigEndian(typ)
		return ast, nil
	}

	var offsets []uint32

	prev := typ
	for i, j := len(exprStack)-2, -1; i >= 0; i-- {
		var (
			prevName string
			member   *btf.Member
			offset   uint32
			err      error
		)

		ptr, useArrow := prev.(*btf.Pointer)
		if useArrow {
			prev = mybtf.UnderlyingType(ptr.Target)
		}

		expr := exprStack[i]
		switch v := prev.(type) {
		case *btf.Struct:
			member, err = mybtf.FindStructMember(v, expr.Text)
			prevName = v.Name
		case *btf.Union:
			member, err = mybtf.FindUnionMember(v, expr.Text)
			prevName = v.Name
		default:
			return ast, fmt.Errorf("unexpected type %T of %s(%+v)", v, expr.Text, prev)
		}
		if err != nil {
			return ast, fmt.Errorf("failed to find member %s of %s: %w", expr.Text, prevName, err)
		}

		switch v := prev.(type) {
		case *btf.Struct:
			offset, err = mybtf.StructMemberOffset(v, expr.Text)
		case *btf.Union:
			offset, err = mybtf.UnionMemberOffset(v, expr.Text)
		}
		if err != nil {
			return ast, fmt.Errorf("failed to get offset of member %s of %s: %w", expr.Text, prevName, err)
		}

		prev = mybtf.UnderlyingType(member.Type)

		switch expr.Op {
		case cc.Arrow, cc.Dot:
			if !useArrow {
				// access via .
				if j >= 0 {
					offsets[j] += offset
				} else {
					return ast, fmt.Errorf("unexpected access via .: %s", expr)
				}
			} else {
				// access via ->
				offsets = append(offsets, offset)
				j++
			}

			if i == 0 {
				ast.offsets = offsets
				ast.member = member
				ast.lastField = prev
				ast.bigEndian = mybtf.IsBigEndian(member.Type)
				return ast, nil
			}

		default:
			// protected by validateLeftOperand()
			return ast, fmt.Errorf("unexpected operator: %s", expr.Op)
		}
	}

	return ast, fmt.Errorf("unexpected expression: %s", expr)
}

func offset2insns(insns asm.Instructions, offsets []uint32) asm.Instructions {
	lastIndex := len(offsets) - 1
	for i := 0; i <= lastIndex; i++ {
		if offsets[i] != 0 {
			insns = append(insns, asm.Add.Imm(asm.R3, int32(offsets[i]))) // r3 += offset
		}
		insns = append(insns,
			asm.Mov.Imm(asm.R2, 8),                      // r2 = 8; always read 8 bytes
			asm.Mov.Reg(asm.R1, asm.R10),                // r1 = r10
			asm.Add.Imm(asm.R1, -8),                     // r1 = r10 - 8
			asm.FnProbeReadKernel.Call(),                // bpf_probe_read_kernel(r1, 8, r3)
			asm.LoadMem(asm.R3, asm.R10, -8, asm.DWord), // r3 = *(r10 - 8)
		)
		if i != lastIndex { // not last member access
			insns = append(insns,
				asm.JEq.Imm(asm.R3, 0, labelExitFail), // if r3 == 0, goto __exit
			)
		}
	}

	return insns
}

type tgtInfo struct {
	constant  uint64
	typ       btf.Type
	sizof     int
	bigEndian bool
}

func tgt2insns(insns asm.Instructions, tgt tgtInfo) (asm.Instructions, uint64) {
	const leftOperandReg = asm.R3

	tgtConst := tgt.constant
	switch tgt.sizof {
	case 1:
		tgtConst = uint64(uint8(tgtConst))

		insns = append(insns,
			asm.And.Imm(leftOperandReg, 0xFF), // r3 &= 0xff
		)
	case 2:
		tgtConst = uint64(uint16(tgtConst))
		if tgt.bigEndian {
			tgtConst = uint64(h2ns(uint16(tgtConst)))
		}

		insns = append(insns,
			asm.And.Imm(leftOperandReg, 0xFFFF), // r3 &= 0xffff
		)
	case 4:
		tgtConst = uint64(uint32(tgtConst))
		if tgt.bigEndian {
			tgtConst = uint64(h2nl(uint32(tgtConst)))
		}

		insns = append(insns,
			asm.LSh.Imm(leftOperandReg, 32), // r3 <<= 32
			asm.RSh.Imm(leftOperandReg, 32), // r3 >>= 32
		)

	case 8:
		if tgt.bigEndian {
			tgtConst = h2nll(tgtConst)
		}
	}

	return insns, tgtConst
}

func op2insns(insns asm.Instructions, op cc.ExprOp, tgt tgtInfo) (asm.Instructions, error) {
	isSigned := false
	intType, isInt := tgt.typ.(*btf.Int)
	if isInt {
		isSigned = intType.Encoding == btf.Signed
	}

	const leftOperandReg = asm.R3

	var jmpOpCode asm.JumpOp
	switch op {
	case cc.Eq, cc.EqEq:
		// if r3 == tgtConst, goto __return
		jmpOpCode = asm.JEq

	case cc.NotEq:
		// if r3 != tgtConst, goto __return
		jmpOpCode = asm.JNE

	case cc.Lt:
		// if r3 < tgtConst, goto __return
		if isSigned {
			jmpOpCode = asm.JSLT
		} else {
			jmpOpCode = asm.JLT
		}

	case cc.LtEq:
		// if r3 <= tgtConst, goto __return
		if isSigned {
			jmpOpCode = asm.JSLE
		} else {
			jmpOpCode = asm.JLE
		}

	case cc.Gt:
		// if r3 > tgtConst, goto __return
		if isSigned {
			jmpOpCode = asm.JSGT
		} else {
			jmpOpCode = asm.JGT
		}

	case cc.GtEq:
		// if r3 >= tgtConst, goto __return
		if isSigned {
			jmpOpCode = asm.JSGE
		} else {
			jmpOpCode = asm.JGE
		}

	default:
		return nil, fmt.Errorf("unexpected operator: %s; must be one of =, ==, !=, <, <=, >, >=", op)
	}

	insns = append(insns,
		asm.Mov.Imm(asm.R0, 1), // r0 = 1
		jmpOpCode.Imm(leftOperandReg, int32(tgt.constant), labelReturn),
	)

	return insns, nil
}

func compile(expr *cc.Expr, typ btf.Type) (asm.Instructions, error) {
	if expr == nil || expr.Right == nil {
		return nil, fmt.Errorf("expression or right operand is nil")
	}

	tgtConst, err := parseNumber(expr.Right.Text)
	if err != nil {
		return nil, fmt.Errorf("failed to parse right operand as number: %w", err)
	}

	ast, err := expr2offset(expr, typ)
	if err != nil {
		return nil, fmt.Errorf("failed to convert expr to access offsets: %w", err)
	}

	typofLastField := mybtf.UnderlyingType(ast.lastField)
	switch typofLastField.(type) {
	case *btf.Int, *btf.Enum, *btf.Pointer:
	default:
		return nil, fmt.Errorf("unexpected type of last field: %s", typofLastField)
	}

	if isMemberBitfield(ast.member) {
		return nil, fmt.Errorf("unexpected member access of bitfield")
	}

	var sizofLastField int
	if ast.member != nil && ast.member.BitfieldSize != 0 {
		sizofLastField = int(ast.member.BitfieldSize.Bytes())
	} else {
		sizofLastField, err = btf.Sizeof(typofLastField)
		if err != nil {
			return nil, fmt.Errorf("failed to get size of last field type: %w", err)
		}
	}
	switch sizofLastField /* byte */ {
	case 1, 2, 4, 8:
	default:
		return nil, fmt.Errorf("unexpected size %d of last field type %s", sizofLastField, typofLastField)
	}

	// Use R1/R2/R3 caller-saved registers directly.

	var insns asm.Instructions
	insns = append(insns,
		asm.Mov.Reg(asm.R3, asm.R1), // r3 = r1
	)

	insns = offset2insns(insns, ast.offsets)

	tgt := tgtInfo{tgtConst, typofLastField, sizofLastField, ast.bigEndian}
	insns, tgt.constant = tgt2insns(insns, tgt)
	insns, err = op2insns(insns, expr.Op, tgt)
	if err != nil {
		return nil, fmt.Errorf("failed to convert operator to instructions: %w", err)
	}

	insns = append(insns,
		asm.Mov.Imm(asm.R0, 0).WithSymbol(labelExitFail), // r0 = 0; __exit
		asm.Return().WithSymbol(labelReturn),             // return; __return
	)

	return insns, nil
}

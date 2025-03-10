// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package bice

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

type AccessOptions struct {
	Insns     asm.Instructions
	Expr      string
	Type      btf.Type
	Src       asm.Register
	Dst       asm.Register
	LabelExit string
}

type AccessResult struct {
	Insns     asm.Instructions
	LabelUsed bool
}

func Access(opts AccessOptions) (AccessResult, error) {
	if opts.Expr == "" || opts.Type == nil || opts.LabelExit == "" {
		return AccessResult{}, fmt.Errorf("invalid options")
	}

	ast, err := parse(opts.Expr)
	if err != nil {
		return AccessResult{}, fmt.Errorf("failed to compile expression %s: %w", opts.Expr, err)
	}

	err = validateLeftOperand(ast)
	if err != nil {
		return AccessResult{}, fmt.Errorf("expression is not struct/union member access: %w", err)
	}

	offsets, err := expr2offset(ast, opts.Type)
	if err != nil {
		return AccessResult{}, fmt.Errorf("failed to convert expression to offsets: %w", err)
	}

	if len(offsets.offsets) == 0 {
		return AccessResult{}, fmt.Errorf("expr should be struct/union member access")
	}

	size, err := checkLastField(offsets.member, offsets.lastField)
	if err != nil {
		return AccessResult{}, err
	}

	insns := opts.Insns
	if opts.Src != asm.R3 {
		insns = append(insns, asm.Mov.Reg(asm.R3, opts.Src))
	}
	insns, labelUsed := offset2insns(insns, offsets.offsets, opts.Dst, opts.LabelExit)

	tgt := tgtInfo{0, offsets.lastField, size, offsets.bigEndian}
	insns, _ = tgt2insns(insns, tgt, opts.Dst)

	return AccessResult{
		Insns:     insns,
		LabelUsed: labelUsed,
	}, nil
}

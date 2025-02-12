// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bice

import (
	"testing"

	"github.com/leonhwangprojects/bice/internal/test"
	"rsc.io/c2go/cc"
)

func TestValidateOperator(t *testing.T) {
	tests := []struct {
		name  string
		op    cc.ExprOp
		valid bool
	}{
		{name: "eq", op: cc.Eq, valid: true},
		{name: "eqeq", op: cc.EqEq, valid: true},
		{name: "ne", op: cc.NotEq, valid: true},
		{name: "lt", op: cc.Lt, valid: true},
		{name: "le", op: cc.LtEq, valid: true},
		{name: "gt", op: cc.Gt, valid: true},
		{name: "ge", op: cc.GtEq, valid: true},

		{name: "add", op: cc.Add, valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOperator(tt.op)
			test.AssertEqual(t, err == nil, tt.valid)
		})
	}
}

func TestValidateLeftOperand(t *testing.T) {
	tests := []struct {
		name  string
		left  *cc.Expr
		valid bool
	}{
		{name: "nil", left: nil, valid: true},
		{name: "leaf", left: &cc.Expr{}, valid: true},
		{name: "right operand", left: &cc.Expr{Right: &cc.Expr{}}, valid: false},
		{name: "dot", left: &cc.Expr{Op: cc.Dot}, valid: true},
		{name: "arrow", left: &cc.Expr{Op: cc.Arrow}, valid: true},
		{name: "number op", left: &cc.Expr{Op: cc.Number, Left: &cc.Expr{}}, valid: false},
		{name: "skb->dev", left: &cc.Expr{Op: cc.Arrow, Text: "dev", Left: &cc.Expr{Text: "skb"}}, valid: true},
		{name: "a == b", left: &cc.Expr{Op: cc.EqEq, Left: &cc.Expr{Text: "a"}, Right: &cc.Expr{Text: "b"}}, valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLeftOperand(tt.left)
			test.AssertEqual(t, err == nil, tt.valid)
		})
	}
}

func TestValidateRightOperand(t *testing.T) {
	tests := []struct {
		name  string
		right *cc.Expr
		valid bool
	}{
		{name: "number", right: &cc.Expr{Op: cc.Number, Text: "0x1234"}, valid: true},
		{name: "invalid number", right: &cc.Expr{Op: cc.Number, Text: "1234a"}, valid: false},
		{name: "add", right: &cc.Expr{Op: cc.Add}, valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRightOperand(tt.right)
			test.AssertEqual(t, err == nil, tt.valid)
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name  string
		expr  *cc.Expr
		valid bool
	}{
		{name: "eq", expr: &cc.Expr{Op: cc.Eq, Left: &cc.Expr{Text: "skb"}, Right: &cc.Expr{Op: cc.Number, Text: "0xffffedcba987"}}, valid: true},
		{name: "lt", expr: &cc.Expr{Op: cc.Lt, Left: &cc.Expr{Text: "skb"}, Right: &cc.Expr{Op: cc.Number, Text: "0xffffedcba987"}}, valid: true},
		{name: "nil left operand", expr: &cc.Expr{Op: cc.Eq, Right: &cc.Expr{Op: cc.Number, Text: "0xffffedcba987"}}, valid: false},
		{name: "nil right operand", expr: &cc.Expr{Op: cc.Eq, Left: &cc.Expr{Text: "skb"}}, valid: false},
		{name: "invalid operator", expr: &cc.Expr{Op: cc.Add, Left: &cc.Expr{Text: "skb"}, Right: &cc.Expr{Op: cc.Number, Text: "0xffffedcba987"}}, valid: false},
		{name: "invalid left operand", expr: &cc.Expr{Op: cc.Eq, Left: &cc.Expr{Left: &cc.Expr{Text: "skb"}, Op: cc.Add}, Right: &cc.Expr{Op: cc.Number, Text: "0xffffedcba987"}}, valid: false},
		{name: "invalid right operand", expr: &cc.Expr{Op: cc.Eq, Left: &cc.Expr{Text: "skb"}, Right: &cc.Expr{Op: cc.Eq, Left: &cc.Expr{Text: "skb"}}}, valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(tt.expr)
			test.AssertEqual(t, err == nil, tt.valid)
		})
	}
}

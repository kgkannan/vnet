// autogenerated: do not edit!
// generated from gentemplate [gentemplate -d Package=ip6 -id Fib -d VecType=FibVec -d Type=*Fib github.com/platinasystems/go/elib/vec.tmpl]

// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ip

import (
	"github.com/platinasystems/elib"
)

type FibVec []*Fib

func (p *FibVec) Resize(n uint) {
	old_cap := uint(cap(*p))
	new_len := uint(len(*p)) + n
	if new_len > old_cap {
		new_cap := elib.NextResizeCap(new_len)
		q := make([]*Fib, new_len, new_cap)
		copy(q, *p)
		*p = q
	}
	*p = (*p)[:new_len]
}

func (p *FibVec) validate(new_len uint, zero *Fib) **Fib {
	old_cap := uint(cap(*p))
	old_len := uint(len(*p))
	if new_len <= old_cap {
		// Need to reslice to larger length?
		if new_len > old_len {
			*p = (*p)[:new_len]
			for i := old_len; i < new_len; i++ {
				(*p)[i] = zero
			}
		}
		return &(*p)[new_len-1]
	}
	return p.validateSlowPath(zero, old_cap, new_len, old_len)
}

func (p *FibVec) validateSlowPath(zero *Fib, old_cap, new_len, old_len uint) **Fib {
	if new_len > old_cap {
		new_cap := elib.NextResizeCap(new_len)
		q := make([]*Fib, new_cap, new_cap)
		copy(q, *p)
		for i := old_len; i < new_cap; i++ {
			q[i] = zero
		}
		*p = q[:new_len]
	}
	if new_len > old_len {
		*p = (*p)[:new_len]
	}
	return &(*p)[new_len-1]
}

func (p *FibVec) Validate(i uint) **Fib {
	var zero *Fib
	return p.validate(i+1, zero)
}

func (p *FibVec) ValidateInit(i uint, zero *Fib) **Fib {
	return p.validate(i+1, zero)
}

func (p *FibVec) ValidateLen(l uint) (v **Fib) {
	if l > 0 {
		var zero *Fib
		v = p.validate(l, zero)
	}
	return
}

func (p *FibVec) ValidateLenInit(l uint, zero *Fib) (v **Fib) {
	if l > 0 {
		v = p.validate(l, zero)
	}
	return
}

func (p *FibVec) ResetLen() {
	if *p != nil {
		*p = (*p)[:0]
	}
}

func (p FibVec) Len() uint { return uint(len(p)) }

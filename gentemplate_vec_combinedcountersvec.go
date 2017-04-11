// autogenerated: do not edit!
// generated from gentemplate [gentemplate -d Package=vnet -id combinedCountersVec -d VecType=CombinedCountersVec -d Type=CombinedCounters github.com/platinasystems/go/elib/vec.tmpl]

// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vnet

import (
	"github.com/platinasystems/go/elib"
)

type CombinedCountersVec []CombinedCounters

func (p *CombinedCountersVec) Resize(n uint) {
	c := elib.Index(cap(*p))
	l := elib.Index(len(*p)) + elib.Index(n)
	if l > c {
		c = elib.NextResizeCap(l)
		q := make([]CombinedCounters, l, c)
		copy(q, *p)
		*p = q
	}
	*p = (*p)[:l]
}

func (p *CombinedCountersVec) validate(new_len uint, zero CombinedCounters) *CombinedCounters {
	c := elib.Index(cap(*p))
	lʹ := elib.Index(len(*p))
	l := elib.Index(new_len)
	if l <= c {
		// Need to reslice to larger length?
		if l > lʹ {
			*p = (*p)[:l]
			for i := lʹ; i < l; i++ {
				(*p)[i] = zero
			}
		}
		return &(*p)[l-1]
	}
	return p.validateSlowPath(zero, c, l, lʹ)
}

func (p *CombinedCountersVec) validateSlowPath(zero CombinedCounters, c, l, lʹ elib.Index) *CombinedCounters {
	if l > c {
		cNext := elib.NextResizeCap(l)
		q := make([]CombinedCounters, cNext, cNext)
		copy(q, *p)
		for i := c; i < cNext; i++ {
			q[i] = zero
		}
		*p = q[:l]
	}
	if l > lʹ {
		*p = (*p)[:l]
	}
	return &(*p)[l-1]
}

func (p *CombinedCountersVec) Validate(i uint) *CombinedCounters {
	var zero CombinedCounters
	return p.validate(i+1, zero)
}

func (p *CombinedCountersVec) ValidateInit(i uint, zero CombinedCounters) *CombinedCounters {
	return p.validate(i+1, zero)
}

func (p *CombinedCountersVec) ValidateLen(l uint) (v *CombinedCounters) {
	if l > 0 {
		var zero CombinedCounters
		v = p.validate(l, zero)
	}
	return
}

func (p *CombinedCountersVec) ValidateLenInit(l uint, zero CombinedCounters) (v *CombinedCounters) {
	if l > 0 {
		v = p.validate(l, zero)
	}
	return
}

func (p CombinedCountersVec) Len() uint { return uint(len(p)) }

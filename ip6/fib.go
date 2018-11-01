// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ip6

import (
	//"github.com/platinasystems/elib"
	"github.com/platinasystems/elib/dep"
	//"github.com/platinasystems/elib/parse"
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/ip"

	"fmt"
	"net"
)

var masks = compute_masks()

// Maps for prefixes for /0 through /32; key in network byte order.
type MapFib [1 + 128]map[vnet.Uint32]mapFibResult

func compute_masks() (m [129]Address) {
	for l := uint(0); l < uint(len(m)); l++ {
		for i := uint(0); i < l; i++ {
			m[l][i/8] |= uint8(1) << (7 - (i % 8))
		}
	}
	return
}

func (a *Address) MaskLen() (len uint, ok bool) {
	len = ^uint(0)
	j, l := uint(0), uint(0)
	for i := 0; i < AddressBytes; i++ {
		fmt.Printf("Dbg.. check addr=%x\n", a[i])
	}
	for i := 0; i < AddressBytes; i++ {
		m := a[i]
		fmt.Printf("Dbg.. m=%x i=%d j=%d\n", m, i, j)
		if j != 0 {
			if m != 0 {
				fmt.Printf("Dbg.. returning m=%x i=%d j=%d\n", m, i, j)
				return
			}
		} else {
			switch m {
			case 0xff:
				l += 8
			case 0xfe:
				l += 7
			case 0xfc:
				l += 6
			case 0xf8:
				l += 5
			case 0xf0:
				l += 4
			case 0xe0:
				l += 3
			case 0xc0:
				l += 2
			case 0x80:
				l += 1
			case 0:
				l += 0
			default:
				fmt.Printf("Dbg.. returning2 m=%x i=%d j=%d\n", m, i, j)
				return
			}
			if m != 0xff {
				j++
			}
		}
	}
	len = l
	ok = true
	return
}

func (v *Address) MaskedString(r vnet.MaskedStringer) (s string) {
	m := r.(*Address)
	s = v.String() + "/"
	if l, ok := m.MaskLen(); ok {
		s += fmt.Sprintf("%d", l)
	} else {
		s += fmt.Sprintf("%s", m.String())
	}
	return
}

func AddressMaskForLen(l uint) Address       { return masks[l] }
func (p *Prefix) MaskAsAddress() (a Address) { return AddressMaskForLen(uint(p.Len)) }

type Prefix struct {
	Address
	Len uint32
}

func (p *Prefix) SetLen(l uint) { p.Len = uint32(l) }
func (a *Address) toPrefix() (p Prefix) {
	p.Address = *a
	return
}
func (p Prefix) ToIPNet() (ipn net.IPNet) {
	mask := AddressMaskForLen(uint(p.Len))
	// an empty ipn has nil for Mask and IP so use append
	ipn.Mask = append(mask[:0:0], mask[:]...)
	ipn.IP = append(p.Address[:0:0], p.Address[:]...)
	return
}

func FromIp6Prefix(i *ip.Prefix) (p Prefix) {
	copy(p.Address[:], i.Address[:AddressBytes])
	p.Len = i.Len
	return
}
func (p *Prefix) ToIpPrefix() (i ip.Prefix) {
	copy(i.Address[:], p.Address[:])
	i.Len = p.Len
	return
}

type mapFibResult struct {
	adj ip.Adj
	nh  mapFibResultNextHop
}

type idst struct {
	a Address
	i ip.FibIndex
}

type ipre struct {
	p Prefix
	i ip.FibIndex
}

type NextHopper interface {
	ip.AdjacencyFinalizer
	NextHopFibIndex(m *Main) ip.FibIndex
	NextHopWeight() ip.NextHopWeight
}

type mapFibResultNextHop map[idst]map[ipre]NextHopper

//go:generate gentemplate -d Package=ip6 -id ply -d PoolType=plyPool -d Type=ply -d Data=plys github.com/platinasystems/elib/pool.tmpl

type Fib struct {
	index ip.FibIndex

	// Map-based fib for general accounting and to maintain mtrie (e.g. setLessSpecific).
	reachable, unreachable MapFib

	// Mtrie for fast lookups.
	mtrie
}

//go:generate gentemplate -d Package=ip6 -id Fib -d VecType=FibVec -d Type=*Fib github.com/platinasystems/elib/vec.tmpl
type fibMain struct {
	fibs FibVec
	// Hooks to call on set/unset.
	fibAddDelHooks      FibAddDelHookVec
	ifRouteAdjIndexBySi map[vnet.Si]ip.Adj
}

type IfAddrAddDelHook func(ia ip.IfAddr, isDel bool)

//go:generate gentemplate -id FibAddDelHook -d Package=ip6 -d DepsType=FibAddDelHookVec -d Type=FibAddDelHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl
//go:generate gentemplate -id IfAddrAddDelHook -d Package=ip6 -d DepsType=IfAddrAddDelHookVec -d Type=IfAddrAddDelHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl

type FibAddDelHook func(i ip.FibIndex, p *Prefix, r ip.Adj, iDel bool)

func (m *fibMain) RegisterFibAddDelHook(f FibAddDelHook, dep ...*dep.Dep) {
	m.fibAddDelHooks.Add(f, dep...)
}

func (m *fibMain) callFibAddDelHooks(fi ip.FibIndex, p *Prefix, r ip.Adj, isDel bool) {
	for i := range m.fibAddDelHooks.hooks {
		m.fibAddDelHooks.Get(i)(fi, p, r, isDel)
	}
}

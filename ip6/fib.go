// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ip6

import (
	"fmt"
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/internal/dbgvnet"
	"github.com/platinasystems/vnet/ip"
	"net"
	"sync"
)

type Prefix struct {
	Address
	Len uint32
}

//TBDIP6: fib optimization to program one link-local address per netns
type LinklocalEntry struct {
	//llipnet net.IPNet
	ref int
}

type LinklocalNetns struct {
	lladdr string
	fi     ip.FibIndex
}

var cached struct {
	masks struct {
		once sync.Once
		val  interface{}
	}
}

var LinklocalUnicast = net.IPNet{
	IP:   net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	Mask: net.IPMask{0xff, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
}

//set to masklen > 129
//Map for link local ipv6 address per namespace
var MapLinklocalNetns map[LinklocalNetns]LinklocalEntry

var masks = compute_masks()

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

func netMask(i uint) Address {
	const nmasks = 129
	cached.masks.once.Do(func() {
		masks := make([]Address, nmasks)
		for j := range masks {
			m := masks[j][:]
			for k := uint(0); k < uint(j); k++ {
				m[k/8] |= uint8(1) << uint(7-uint(k%8))
			}
		}
		cached.masks.val = masks
	})
	if i < nmasks {
		return cached.masks.val.([]Address)[i]
	}
	return masks[0]
}

//DONE:
func AddressMaskForLen(l uint) Address       { return netMask(l) } //{ return masks[l] }
func (p *Prefix) MaskAsAddress() (a Address) { return AddressMaskForLen(uint(p.Len)) }
func LenForAddressMask(mask Address) (l uint) {
	var j int
	j = int(len(cached.masks.val.([]Address)) + 1) //set to masklen > 129
	for j = range cached.masks.val.([]Address) {
		if cached.masks.val.([]Address)[uint(j)] == mask {
			break
		}
	}

	return uint(j)
}

//DONE
func (p *Prefix) Mask() Address { return netMask(uint(p.Len)) }

func (p *Prefix) PrefixToAddress() (addr Address) {
	m := p.Mask()
	for i := 0; i < len(p.Address); i++ {
		addr[i] = p.Address[i] & m[i]
	}

	return addr
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

//type FibAddDelHook func(i ip.FibIndex, p *Prefix, r ip.Adj, isDel bool)
type FibAddDelHook func(i ip.FibIndex, p *net.IPNet, r ip.Adj, isDel bool)
type IfAddrAddDelHook func(ia ip.IfAddr, isDel bool)

func IsIPNetV6Prefix(p *net.IPNet) (flag bool) {
	if ipn := p.IP.To16(); len(ipn) == net.IPv6len {
		flag = true
	}
	return
}

func IPNetToV6Prefix(ipn net.IPNet) (p Prefix) {
	l, _ := ipn.Mask.Size()
	p.Len = uint32(l)
	// p.Address has a length already, so ok to just copy
	copy(p.Address[:], ipn.IP[:])
	return
}

func makeLinklocalKey(p *net.IPNet, fi ip.FibIndex) (k LinklocalNetns) {
	//size, _ := p.Mask.Size()
	//l = uint32(size)
	//for linklocal address, use the string part for the MS 16 bits of
	//address (which is fe80)
	dbgvnet.Adj.Logf("MS 2 bytes [0] %v [1] %v\n", p.IP[0], p.IP[1])
	//llipn = net.IPNet{} //0xff, 0xff,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	//llipn.Mask = []byte{0xff, 0xc0}
	//llipn.IP[0] = p.IP[0] & llipn.Mask[0]
	//llipn.IP[1] = p.IP[1] & llipn.Mask[1]
	k.lladdr = LinklocalUnicast.IP.String()
	k.fi = fi
	dbgvnet.Adj.Logf("llkey = %v\n", k)
	return
}

func getCreateLinklocalEntry(p *net.IPNet, fi ip.FibIndex) (ent LinklocalEntry, found bool) {
	ent = LinklocalEntry{}
	key := makeLinklocalKey(p, fi)
	if MapLinklocalNetns == nil {
		MapLinklocalNetns = make(map[LinklocalNetns]LinklocalEntry)
	}
	if _, found = MapLinklocalNetns[key]; !found {
		//e.llipn.Mask = []byte{0xff, 0xc0}
		//e.llipn.IP[0] = k.IP[0] & llipn.Mask[0]
		//e.llipn.IP[1] = k.IP[1] & llipn.Mask[1]
		ent.ref = 1
	} else {
		ent.ref++
	}
	MapLinklocalNetns[key] = ent
	dbgvnet.Adj.Logf("linklocalMap found %v key %v, entry %v\n", found, key, ent)
	return
}

func deleteLinklocalEntry(k LinklocalNetns) {
	e, found := MapLinklocalNetns[k]
	dbgvnet.Adj.Logf("delete %v linklocalMap key %v, entry %v\n", k, e)
	if found {
		e.ref--
		//delete the linklocal map entry, when the last linklocal address
		//for that namespacei gets deleted
		if e.ref == 0 {
			dbgvnet.Adj.Logf("freed %v linklocalMap key %v\n", k)
			delete(MapLinklocalNetns, k)
		}
	}
}

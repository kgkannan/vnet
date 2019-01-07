// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ip6

import (
	"github.com/platinasystems/elib/dep"
	"github.com/platinasystems/elib/parse"
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/internal/dbgvnet"
	"github.com/platinasystems/vnet/ip"

	"bytes"
	"fmt"
	"net"
	"sync"
)

var masks = compute_masks()

// Maps for prefixes for /0 through /32; key in network byte order.
type MapFib [1 + 128]map[Address]mapFibResult

//set to masklen > 129
//Map for link local ipv6 address per namespace
var MapIp6Linklocal map[Ip6NetnsKey]int

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

/* progress tracking markers: DONE/OK => done, TBD or unmarked => revisit, PRG/MOD - in-progress,
   DEL/del - remove (changes are done appropriately/elsewhere)
   NOTE: remove all commented out code after integration with FDB changes
*/
/* begin: copy-paste from ip4/fib.go */

//TBDIP6: done
func (p *Prefix) Matches(q *Prefix) bool {
	m1 := p.Mask()
	m2 := q.Mask()
	for i := 0; i < len(p.Address); i++ {
		if p.Address[i]&m1[i] != q.Address[i]&m2[i] {
			return false
		}
	}
	return true
}

//DONE
func (p *Prefix) IsEqual(q *Prefix) bool {
	/*
		if p.len != q.len {
			return false
		}

		for i := 0; i < p.Len; i++ {
			if p.Address[i] != q.Address[i] {
				return false
			}
		}

		return true
	*/

	return p.Len == q.Len && bytes.Equal(p.Address[:], q.Address[:])
}

//PRG
func (dst *Address) MatchesPrefix(p *Prefix) bool {
	mask_addr := p.MaskAsAddress()
	src_addr := p.Address
	for i := 0; i < 4; i++ {
		if (dst.AsUint32(uint(i))^src_addr.AsUint32(uint(i)))&mask_addr.AsUint32(uint(i)) != 0 {
			return false
		}
	}
	/*
		if p.Len == q.Len {
			mask_p := p.MaskAsAddress()
			mask_q := q.MaskAsAddress()
			for i := 0; i < 16; i++ {
				if p.Address[i]&mask_p[i] != q.Address[i]&mask_q[i] {
					return false
				}
			}
			return true
		}

		return false
	*/

	return true
}

func (p *Prefix) LessThan(q *Prefix) bool {
	if cmp := p.Address.Diff(&q.Address); cmp != 0 {
		return cmp < 0
	}
	return p.Len < q.Len
}

//Add adds offset to prefix.  For example, 1.2.3.0/24 + 1 = 1.2.4.0/24.
//TBD:
/*
func (p *Prefix) Add(offset uint) (q Prefix) {
	a := p.Address.AsUint32().ToHost()
	a += uint32(offset << (32 - p.Len))
	q = *p
	q.Address.FromUint32(vnet.Uint32(a).FromHost())
	return
}
*/

func ToIp6Prefix(i *ip.Prefix) (p Prefix) {
	copy(p.Address[:], i.Address[:AddressBytes])
	p.Len = i.Len
	return
}

func (p *Prefix) ToIpPrefix() (i ip.Prefix) {
	copy(i.Address[:], p.Address[:])
	i.Len = p.Len
	return
}

func Ip6PrefixToIPNet(p *Prefix) *net.IPNet {
	ipBuf := make([]byte, 128)
	maskBuf := make([]byte, 128)
	/*
		for i := 0; i < 128; i++ {
			ipBuf[i] = p.Address[i]
			maskBuf[i] = p.Address[i]
		}
	*/
	ip6_mask := p.Mask()
	copy(ipBuf[:], p.Address[:])
	copy(maskBuf[:], ip6_mask[:])

	return &net.IPNet{net.IP(ipBuf), net.IPMask(maskBuf)}
}

type mapFibResult struct {
	adj ip.Adj
	nh  mapFibResultNextHop
}

type Ip6NetnsKey struct {
	ip.Prefix
	ip.FibIndex
}

var cached struct {
	masks struct {
		once sync.Once
		val  interface{}
	}
}

/* Cache of prefix length network masks: entry LEN has high LEN bits set.
   so, 10/8 has top 8 bits set.
addr = 1:2:3:4:5:6:7:8:9:10:11:12:13:14:15:16
masklen = 0 => mask = 0x0 .. 0x0 (all zeros)
masklen = 1 => mask = 0x80 .. 0x0 (all zeros except bit 7 in b[0])
masklen = 2 => mask = 0xc0 .. 0x0 (all zeros except bit 7,6 b[0])
masklen = 3 => mask = 0xe0 .. 0x0 (all zeros except bit 7,6,5 b[0])
..
masklen = 8 => mask = 0xff 0x00 0x0
..
masklen = 9 => mask = 0xf8 .. 0x0 (all zeros except bit 7 in b[1])
masklen = a => mask = 0xfc .. 0x0 (all zeros except bit 7,6 in b[1])
masklen = b => mask = 0xfe .. 0x0 (all zeros except bit 7,6,5 in b[1])
masklen = c => mask = 0xff 0x00 0x0
*/
//TBDIP6: DONE
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

//DONE
func (p *Prefix) Mask() Address { return netMask(uint(p.Len)) }

func (p *Prefix) PrefixToAddress() (addr Address) {
	m := p.Mask()
	for i := 0; i < len(p.Address); i++ {
		addr[i] = p.Address[i] & m[i]
	}

	return addr
}

//DONE:
func (p *Prefix) mapFibKey() Address {
	return (p.PrefixToAddress())
	/*
		m := p.Mask()
		for i := 0; i < len(p.Address); i++ {
			addr[i] = p.Address[i] & m[i]
		}

		return addr
	*/
	/*
		var ip6_key ip6_hlen
		var i, j uint

		for i = 0; i < 2; i++ {
			for j = 0; j < 2; j++ {
				ip6_key[i] |= p.Address.AsUint32(j) & p.Mask.AsUint32(j)
			}
		}
		return ip6_key //p.Address.AsUint32() & p.Mask()
	*/
}

//TBDIP6: DONE
func (p *Prefix) ApplyMask() (q *Prefix) {
	pm := Prefix{}
	//pm.Address.FromUint32(p.Address.AsUint32() & p.Mask())
	pm.Address = p.PrefixToAddress()
	pm.Len = p.Len
	q = &pm
	return
}

//TBDIP6: DONE
func (a *Address) Mask(l uint) (v Address) {
	//v.FromUint32(a.AsUint32() & netMask(l))
	m := netMask(uint(l))
	for i := 0; i < len(a); i++ {
		v[i] = a[i] & m[i]
	}

	return
}

func (m *MapFib) validateLen(l uint32) {
	if m[l] == nil {
		m[l] = make(map[Address]mapFibResult)
	}
}

//TBDIP6: TBD
func (m *MapFib) Set(p *Prefix, newAdj ip.Adj) (oldAdj ip.Adj, ok bool) {
	l := p.Len
	m.validateLen(l)
	k := Address{0} //vnet.Uint32(0)
	//k := p.mapFibKey()
	var r mapFibResult
	if r, ok = m[l][k]; !ok {
		oldAdj = ip.AdjNil
	} else {
		oldAdj = r.adj
	}
	ok = true // set never fails
	r.adj = newAdj
	m[l][k] = r
	return
}

//TBDIP6: TBD
func (m *MapFib) Unset(p *Prefix) (oldAdj ip.Adj, ok bool) {
	//k := p.mapFibKey()
	k := Address{0} //vnet.Uint32(0)
	var r mapFibResult
	if r, ok = m[p.Len][k]; ok {
		oldAdj = r.adj
		delete(m[p.Len], k)
	} else {
		oldAdj = ip.AdjNil
	}
	return
}

//TBDIP6: TBD
func (m *MapFib) Get(p *Prefix) (r mapFibResult, ok bool) {
	//r, ok = m[p.Len][p.mapFibKey()]
	r, ok = m[p.Len][Address{0}]
	return
}

//TBDIP6: TBD
func (m *MapFib) Lookup(a Address) (r mapFibResult, p Prefix, ok bool) {
	p = a.toPrefix()
	for l := 32; l >= 0; l-- {
		if m[l] == nil {
			continue
		}
		p.SetLen(uint(l))
		k := Address{0} //vnet.Uint32(0)
		//k := p.mapFibKey()
		if r, ok = m[l][k]; ok {
			//p.Address.FromUint32(k)
			return
		}
	}
	r = mapFibResult{adj: ip.AdjMiss}
	p = Prefix{}
	return
}

//TBDIP6: TBD
// Reachable means that all next-hop adjacencies are rewrites.
func (f *MapFib) lookupReachable(m *Main, a Address) (r mapFibResult, p Prefix, reachable, err bool) {
	if r, p, reachable = f.Lookup(a); reachable {
		as := m.GetAdj(r.adj)
		for i := range as {
			err = as[i].IsLocal()
			reachable = as[i].IsRewrite()
			if !reachable {
				break
			}
		}
	}
	return
}

//TBDIP6: TBD
// Calls function for each more specific prefix matching given key.
func (m *MapFib) foreachMatchingPrefix(key *Prefix, fn func(p *Prefix, r mapFibResult)) {
	p := Prefix{Address: key.Address}
	for l := key.Len + 1; l <= 32; l++ {
		p.Len = l
		//if r, ok := m[l][p.mapFibKey()]; ok {
		if r, ok := m[l][Address{0}]; ok {
			fn(&p, r)
		}
	}
}

//TBDIP6: TBD
func (m *MapFib) foreach(fn func(p *Prefix, r mapFibResult)) {
	var p Prefix
	for l := 32; l >= 0; l-- {
		p.Len = uint32(l)
		//for k, r := range m[l] {
		for _, r := range m[l] {
			//p.Address.FromUint32(k)
			fn(&p, r)
		}
	}
}

//TBDIP6: TBD
func (m *MapFib) reset() {
	for i := range m {
		m[i] = nil
	}
}

func (m *MapFib) clean(fi ip.FibIndex) {
	for i := range m {
		for _, r := range m[i] {
			for dst, dstMap := range r.nh {
				for dp := range dstMap {
					if dp.i == fi {
						delete(dstMap, dp)
					}
				}
				if len(dstMap) == 0 {
					delete(r.nh, dst)
				}
			}
		}
	}
}

type Fib struct {
	index ip.FibIndex

	// Map-based fib for general accounting and to maintain mtrie (e.g. setLessSpecific).
	reachable, unreachable MapFib

	// Mtrie for fast lookups.
	mtrie
}

//go:generate gentemplate -d Package=ip6 -id Fib -d VecType=FibVec -d Type=*Fib github.com/platinasystems/elib/vec.tmpl

// Total number of routes in FIB.
func (f *Fib) Len() (n uint) {
	for i := range f.reachable {
		n += uint(len(f.reachable[i]))
	}
	return
}

type IfAddrAddDelHook func(ia ip.IfAddr, isDel bool)

//go:generate gentemplate -id FibAddDelHook -d Package=ip6 -d DepsType=FibAddDelHookVec -d Type=FibAddDelHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl
//go:generate gentemplate -id IfAddrAddDelHook -d Package=ip6 -d DepsType=IfAddrAddDelHookVec -d Type=IfAddrAddDelHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl

func (f *Fib) addDel(main *Main, p *Prefix, r ip.Adj, isDel bool) (oldAdj ip.Adj, ok bool) {
	if isDel {
		/* TBDIP6: remove entry from MapIp6Linklocal[key] */
		dbgvnet.Adj.Logf("%v prefix %v adj %v delete: call fe1 hooks, addDelReachable\n", f.index.Name(&main.Main), p.String(), r)
		// Call hooks before delete.
		main.callFibAddDelHooks(f.index, p, r, isDel)
		f.addDelReachable(main, p, r, isDel)
	}

	// Add/delete in map fib.
	if isDel {
		oldAdj, ok = f.reachable.Unset(p)
	} else {
		oldAdj, ok = f.reachable.Set(p, r)
	}

	// Add/delete in mtrie fib.
	/*
			m := &f.mtrie

			if len(m.plys) == 0 {
				m.init()
			}

			s := addDelLeaf{
				key:    p.Address.Mask(uint(p.Len)),
				keyLen: uint8(p.Len),
				result: r,
			}

		if isDel {
			if p.Len == 0 {
				m.defaultLeaf = emptyLeaf
			} else {
				s.unset(m)
				f.setLessSpecific(p)
			}
		} else {
			if p.Len == 0 {
				m.defaultLeaf = setResult(s.result)
			} else {
				s.set(m)
			}
		}
	*/

	// Call hooks after add.
	if !isDel {
		/* TBDIP6: check for link-local ip6 address */
		//q := ToIp6Prefix(p)
		ll_ipnet := Ip6PrefixToIPNet(p)
		if ll_ipnet.IP.IsLinkLocalUnicast() {
			var key Ip6NetnsKey
			copy(key.Address[:], p.Address[:])
			key.FibIndex = f.index
			//key := Ip6NetnsKey{Address: p.Address, FibIndex: f.index}
			if _, found := MapIp6Linklocal[key]; found {
				fmt.Printf("ip6 link local entry exists for fib\n")
				return
			}
		}

		dbgvnet.Adj.Logf("%v prefix %v adj %v add: call fe1 hooks, addDelReachable\n", f.index.Name(&main.Main), p.String(), r)
		main.callFibAddDelHooks(f.index, p, r, isDel)
		f.addDelReachable(main, p, r, isDel)
	}

	return
}

type NextHopper interface {
	ip.AdjacencyFinalizer
	NextHopFibIndex(m *Main) ip.FibIndex
	NextHopWeight() ip.NextHopWeight
}

type idst struct {
	a Address
	i ip.FibIndex
}

type ipre struct {
	p Prefix
	i ip.FibIndex
}

// idst is the destination or nh address and namespace
// ipre is the prefix that has idst as its nh
type mapFibResultNextHop map[idst]map[ipre]NextHopper

//TBDIP6: TBD
func (x *mapFibResult) addDelNextHop(m *Main, pf *Fib, p Prefix, a Address, r NextHopper, isDel bool) {
	id := idst{a: a, i: r.NextHopFibIndex(m)}
	ip := ipre{p: p, i: pf.index}

	dbgvnet.Adj.Logf("isDel %v id %v ip %v: before %v\n", isDel, id, ip, x)

	if isDel {
		delete(x.nh[id], ip)
		if len(x.nh[id]) == 0 {
			delete(x.nh, id)
		}
	} else {
		if x.nh == nil {
			x.nh = make(map[idst]map[ipre]NextHopper)
		}
		if x.nh[id] == nil {
			x.nh[id] = make(map[ipre]NextHopper)
		}
		x.nh[id][ip] = r
	}

	dbgvnet.Adj.Logf("after %v\n", x)
}

func (x *mapFibResultNextHop) String() (s string) {
	for a, m := range *x {
		for p, w := range m {
			s += fmt.Sprintf("  %v %v x %d\n", &p, &a.a, w)
		}
	}
	return
}

//TBDIP6: TBD
func (f *Fib) setReachable(m *Main, p *Prefix, pf *Fib, via *Prefix, a Address, r NextHopper, isDel bool) {
	//va, vl := via.Address.AsUint32(), via.Len
	va, vl := Address{0}, via.Len //vnet.Uint32(0), via.Len
	x := f.reachable[vl][va]
	x.addDelNextHop(m, pf, *p, a, r, isDel)
	f.reachable[vl][va] = x
	dbgvnet.Adj.Logf("isDel %v prefix %v via %v nha %v adj %v, new mapFibResult %v\n", isDel, p.String(), via.String(), a, x.adj, x)
}

func (less *mapFibResult) replaceWithLessSpecific(m *Main, f *Fib, more *mapFibResult) {
	for dst, dstMap := range more.nh {
		// Move all destinations from more -> less.
		delete(more.nh, dst)
		if less.nh == nil {
			less.nh = make(map[idst]map[ipre]NextHopper)
		}
		less.nh[dst] = dstMap
		// Replace adjacencies: more -> less.
		for dp, r := range dstMap {
			g := m.fibByIndex(dp.i, false)
			g.replaceNextHop(m, &dp.p, f, more.adj, less.adj, dst.a, r)
		}
	}
}

func (x *mapFibResult) delReachableVia(m *Main, f *Fib) {
	// x is the mapFibResult from reachable (i.e. x is the reachable MapFib)
	// delReachableVia will traverse the map and remove x's address from all the prefixes that uses it as its nexthop address, and add them to unreachable
	// This is also called from addDelUnreachable (i.e. x is the unreachable MapFib) when doing recursive delete; not sure what the purpose is...
	dbgvnet.Adj.Logf("adj %v IsMpAdj %v mapFibResult before: %v\n", x.adj, m.IsMpAdj(x.adj), x)

	for dst, dstMap := range x.nh {
		// dstMap is map of prefixes that uses dst as its nh
		// For each of them, remove nh from prefix and add to unreachable
		for dp, r := range dstMap {
			g := m.fibByIndex(dp.i, false)
			const isDel = true
			ai, ok := g.Get(&dp.p) // Get gets from g.reachable
			if !ok || ai == ip.AdjNil || ai == ip.AdjMiss {
				return
			}
			if m.IsMpAdj(ai) {
				// ai is a mpAdj, use addDelRouteNextHop to delete
				// for mpAdj, addDelRouteNextHop will remove dst from x.nh's map as part of the cleanup and accounting
				// if len(x.nh) ends up 0 after, it will remove x.nh
				g.addDelRouteNextHop(m, &dp.p, dst.a, r, isDel)
			} else {
				// ai is either local, glean, or adjacency from neighbor
				// use addDel directly to delete adjacency
				as := m.GetAdj(ai)
				adjType := "no adjacency found at that adj index"
				if len(as) > 0 {
					adjType = as[0].LookupNextIndex.String()
					// addDel will not remove dst from x.nh's map automatically
					g.addDel(m, &dp.p, ai, true)
				} else {
					fmt.Printf("DEBUG: fib.go delReachableVia: attempt to remove nh %v from prefix %v but unexpected old adjacency %v type %v",
						dst.a, dp.p.String(), ai, adjType)
				}
			}
			// Prefix is now unreachable, add to unreachable, no recurse
			f.addDelUnreachable(m, &dp.p, g, dst.a, r, !isDel, false)
		}
		// Verify that x.nh[id] is not already deleted as part of the cleanup; and if not, delete it
		if x.nh[dst] != nil {
			// delete the etry from x's map
			delete(x.nh, dst)
		}
	}

	dbgvnet.Adj.Logf("adj %v IsMpAdj %v mapFibResult after: %v\n", x.adj, m.IsMpAdj(x.adj), x)
}

func (less *mapFibResult) replaceWithMoreSpecific(m *Main, f *Fib, p *Prefix, adj ip.Adj, more *mapFibResult) {
	for dst, dstMap := range less.nh {
		if dst.a.MatchesPrefix(p) {
			delete(less.nh, dst)
			for dp, r := range dstMap {
				const isDel = false
				g := m.fibByIndex(dp.i, false)
				more.addDelNextHop(m, g, dp.p, dst.a, r, isDel)
				g.replaceNextHop(m, &dp.p, f, less.adj, adj, dst.a, r)
			}
		}
	}
	f.reachable[p.Len][p.mapFibKey()] = *more
}

func (r *mapFibResult) makeReachable(m *Main, f *Fib, p *Prefix, adj ip.Adj) {
	// r is a mapFibResult from unreachable that we will move to reachable here
	for dst, dstMap := range r.nh {
		// find the destination address from r that matches with prefix p
		if dst.a.MatchesPrefix(p) {
			// delete the entry from r's map
			delete(r.nh, dst)
			// dstMap is map of prefixes that has dst as their nh but was not acctually added to the fib table because nh was unreachable
			// For each that match prefix p, actually add nh (i.e. dst.a) to prefix via addDelRouteNextHop which makes nh reachable
			for dp, r := range dstMap {
				g := m.fibByIndex(dp.i, false)
				const isDel = false

				dbgvnet.Adj.Logf("call addDelRouteNextHop prefix %v add nh %v from makeReachable\n",
					dp.p.String(), dst.a)

				// Don't add nh to glean or local
				// FIXME, what to do instead? ignore and print now
				ai, _ := g.Get(&dp.p) // Get gets from g.reachable
				if ai == ip.AdjNil || ai == ip.AdjMiss || m.IsMpAdj(ai) {
					g.addDelRouteNextHop(m, &dp.p, dst.a, r, isDel)
				} else if vnet.AdjDebug {
					as := m.GetAdj(ai)
					adjType := "no adjacency found at that adj index"
					if len(as) > 0 {
						adjType = as[0].LookupNextIndex.String()
					}
					dbgvnet.Adj.Logf("ignore adding nh %v to prefix %v which has has non MpAdj %v of type %v",
						dst.a, dp.p.String(), ai, adjType)
				}
			}
		}
	}
}

func (x *mapFibResult) addUnreachableVia(m *Main, f *Fib, p *Prefix) {
	// don't know how this is used in conjunction with recursive addDelUnreachable
	// seems like if there is a match, it would delete the entry, but then just add it back?
	for dst, dstMap := range x.nh {
		if dst.a.MatchesPrefix(p) {
			delete(x.nh, dst)
			for dp, r := range dstMap {
				g := m.fibByIndex(dp.i, false)
				const isDel = false
				f.addDelUnreachable(m, &dp.p, g, dst.a, r, isDel, false)
			}
		}
	}
}

func (f *Fib) addDelReachable(m *Main, p *Prefix, a ip.Adj, isDel bool) {
	r, _ := f.reachable.Get(p)

	if isDel {
		dbgvnet.Adj.Logf("delete: %v %v adj %v IsMpAdj %v\n", f.index.Name(&m.Main), p.String(), a, m.IsMpAdj(a))
	} else {
		dbgvnet.Adj.Logf("add: %v %v adj %v IsMpAdj %v\n", f.index.Name(&m.Main), p.String(), a, m.IsMpAdj(a))
	}

	// Look up less specific reachable route for prefix.
	lr, _, lok := f.reachable.getLessSpecific(p)
	if isDel {
		if lok {
			dbgvnet.Adj.Logf("delete: %v %v adj %v replaceWithLessSpecific lr %v r %v\n",
				f.index.Name(&m.Main), p.String(), a, lr, r)
			lr.replaceWithLessSpecific(m, f, &r)
		} else {
			dbgvnet.Adj.Logf("delete: %v %v adj %v delReachableVia r %v\n",
				f.index.Name(&m.Main), p.String(), a, r)
			r.delReachableVia(m, f)
		}
	} else {
		if lok {
			dbgvnet.Adj.Logf("add: %v %v adj %v replaceWithMoreSpecific lr %v r %v\n",
				f.index.Name(&m.Main), p.String(), a, lr, r)
			lr.replaceWithMoreSpecific(m, f, p, a, &r)
		}
		if r, _, ok := f.unreachable.Lookup(p.Address); ok {
			dbgvnet.Adj.Logf("add: %v %v adj %v makeReachable\n", f.index.Name(&m.Main), p.String(), a)
			r.makeReachable(m, f, p, a)
		}
	}
	if isDel {
		dbgvnet.Adj.Logf("delete: %v %v adj %v IsMpAdj %v finished: r %v\n", f.index.Name(&m.Main), p.String(), a, m.IsMpAdj(a), r)
	} else {
		dbgvnet.Adj.Logf("add: %v %v adj %v IsMpAdj %v finished: r %v\n", f.index.Name(&m.Main), p.String(), a, m.IsMpAdj(a), r)
	}
}

func (f *Fib) addDelUnreachable(m *Main, p *Prefix, pf *Fib, a Address, r NextHopper, isDel bool, recurse bool) (err error) {
	//pf is the fib that f is the nexthop of
	//a is the nexthop address from pf
	//r is the nexthopper from pf
	nr, np, _ := f.unreachable.Lookup(a)
	if isDel && recurse {
		// don't recurse on delete for now; can get into infinite loop sometimes
		/*
			nr.delReachableVia(m, f)
		*/
	}
	if !isDel && recurse {
		nr.addUnreachableVia(m, f, p)
	}
	nr.addDelNextHop(m, pf, *p, a, r, isDel)
	f.unreachable.validateLen(np.Len)
	nr.adj = ip.AdjNil
	f.unreachable[np.Len][np.mapFibKey()] = nr
	return
}

// Find first less specific route matching address and insert into mtrie.
func (f *MapFib) getLessSpecific(pʹ *Prefix) (r mapFibResult, p Prefix, ok bool) {
	p = pʹ.Address.toPrefix()

	// No need to consider length 0 since that's not in mtrie.
	for l := int(pʹ.Len) - 1; l >= 1; l-- {
		if f[l] == nil {
			continue
		}
		p.Len = uint32(l)
		k := p.mapFibKey()
		if r, ok = f[l][k]; ok {
			return
		}
	}
	return
}

// Find first less specific route matching address and insert into mtrie.
func (f *Fib) setLessSpecific(pʹ *Prefix) (r mapFibResult, p Prefix, ok bool) {
	r, p, ok = f.reachable.getLessSpecific(pʹ)
	if ok {
		s := addDelLeaf{
			result: r.adj,
			keyLen: uint8(p.Len),
		}
		s.key = p.Address
		s.set(&f.mtrie)
	}
	return
}

func (f *Fib) Get(p *Prefix) (a ip.Adj, ok bool) {
	var r mapFibResult
	// a = 0 is AdjMiss if not found in reachable
	if r, ok = f.reachable[p.Len][p.mapFibKey()]; ok {
		a = r.adj
	}
	return
}

func (f *Fib) Add(m *Main, p *Prefix, r ip.Adj) (ip.Adj, bool) { return f.addDel(m, p, r, false) }
func (f *Fib) Del(m *Main, p *Prefix) (ip.Adj, bool)           { return f.addDel(m, p, ip.AdjMiss, true) }
func (f *Fib) Lookup(a *Address) (r ip.Adj) {
	r = f.mtrie.lookup(a)
	return
}
func (m *Main) Lookup(a *Address, i ip.FibIndex) (r ip.Adj) {
	f := m.fibByIndex(i, true)
	return f.Lookup(a)
}

func (m *Main) setInterfaceAdjacency(a *ip.Adjacency, si vnet.Si, ia ip.IfAddr) {
	sw := m.Vnet.SwIf(si)
	hw := m.Vnet.SupHwIf(sw)
	var h vnet.HwInterfacer
	if hw != nil {
		h = m.Vnet.HwIfer(hw.Hi())
	}

	next := ip.LookupNextRewrite
	noder := &m.rewriteNode
	packetType := vnet.IP4

	if _, ok := h.(vnet.Arper); h == nil || ok {
		next = ip.LookupNextGlean
		noder = &m.arpNode
		packetType = vnet.ARP
		a.Index = uint32(ia)
	}

	a.LookupNextIndex = next
	if h != nil {
		m.Vnet.SetRewrite(&a.Rewrite, si, noder, packetType, nil /* dstAdr meaning broadcast */)
	}
}

type fibMain struct {
	fibs FibVec
	// Hooks to call on set/unset.
	fibAddDelHooks      FibAddDelHookVec
	ifRouteAdjIndexBySi map[vnet.Si]ip.Adj
}

type FibAddDelHook func(i ip.FibIndex, p *Prefix, r ip.Adj, isDel bool)

func (m *fibMain) RegisterFibAddDelHook(f FibAddDelHook, dep ...*dep.Dep) {
	m.fibAddDelHooks.Add(f, dep...)
}

func (m *fibMain) callFibAddDelHooks(fi ip.FibIndex, p *Prefix, r ip.Adj, isDel bool) {
	for i := range m.fibAddDelHooks.hooks {
		m.fibAddDelHooks.Get(i)(fi, p, r, isDel)
	}
}

func (m *Main) fibByIndex(i ip.FibIndex, create bool) (f *Fib) {
	m.fibs.Validate(uint(i))
	if create && m.fibs[i] == nil {
		m.fibs[i] = &Fib{index: i}
	}
	f = m.fibs[i]
	return
}

func (m *Main) fibById(id ip.FibId, create bool) *Fib {
	var (
		i  ip.FibIndex
		ok bool
	)
	if i, ok = m.FibIndexForId(id); !ok {
		i = ip.FibIndex(m.fibs.Len())
	}
	return m.fibByIndex(i, create)
}

func (m *Main) fibBySi(si vnet.Si) *Fib {
	i := m.FibIndexForSi(si)
	return m.fibByIndex(i, true)
}

func (m *Main) validateDefaultFibForSi(si vnet.Si) {
	i := m.ValidateFibIndexForSi(si)
	m.fibByIndex(i, true)
}

func (m *Main) getRoute(p *ip.Prefix, si vnet.Si) (ai ip.Adj, as []ip.Adjacency, ok bool) {
	f := m.fibBySi(si)
	q := ToIp6Prefix(p)
	ai, ok = f.Get(&q)
	if ok {
		as = m.GetAdj(ai)
	}
	return
}

func (m *Main) GetRoute(p *Prefix, si vnet.Si) (ai ip.Adj, ok bool) {
	f := m.fibBySi(si)
	ai, ok = f.Get(p)
	return
}

func (m *Main) getRouteFibIndex(p *ip.Prefix, fi ip.FibIndex) (ai ip.Adj, ok bool) {
	f := m.fibByIndex(fi, false)
	q := ToIp6Prefix(p)
	ai, ok = f.Get(&q)
	return
}

// used by neighbor message to add/del route, e.g. from succesfull arp
func (m *Main) addDelRoute(p *ip.Prefix, fi ip.FibIndex, baseAdj ip.Adj, isDel bool) (oldAdj ip.Adj, err error) {
	createFib := !isDel
	f := m.fibByIndex(fi, createFib)
	q := ToIp6Prefix(p)
	var ok bool

	if isDel {
		dbgvnet.Adj.Logf("addDelRoute delete %v adj %v\n", q.Address.String(), baseAdj.String())
	} else {
		dbgvnet.Adj.Logf("addDelRoute add %v adj %v\n", q.Address.String(), baseAdj.String())
	}

	//addDel the route to/from fib
	oldAdj, ok = f.addDel(m, &q, baseAdj, isDel)

	//don't err if deleting something that has already been deleted
	if !ok {
		if isDel {
			fmt.Printf("DEBUG: fib.go addDelRoute delete prefix %v not fount", q.String())
		} else {
			err = fmt.Errorf("fib.go addDelRoute add prefix %v error addDel", q.String())
		}
	}
	return
}

type NextHop struct {
	Address Address
	Si      vnet.Si
	Weight  ip.NextHopWeight
}

func (n *NextHop) NextHopWeight() ip.NextHopWeight     { return n.Weight }
func (n *NextHop) NextHopFibIndex(m *Main) ip.FibIndex { return m.FibIndexForSi(n.Si) }
func (n *NextHop) FinalizeAdjacency(a *ip.Adjacency)   {}

func (x *NextHop) ParseWithArgs(in *parse.Input, args *parse.Args) {
	v := args.Get().(*vnet.Vnet)
	switch {
	case in.Parse("%v %v", &x.Si, v, &x.Address):
	default:
		panic(fmt.Errorf("expecting INTERFACE ADDRESS; got %s", in))
	}
	x.Weight = 1
	in.Parse("weight %d", &x.Weight)
}

type prefixError struct {
	s string
	p Prefix
}

func (e *prefixError) Error() string { return e.s + ": " + e.p.String() }

func (x *mapFibResult) delNhFromMatchingPrefix(m *Main, f *Fib, p *Prefix) {
	// x is the mapFibResult from reachable or unreachable
	// delReachableVia will traverse the map and remove x's address from prefix p if p uses x.nh.a as a nexthop address
	for id, dstmap := range x.nh {
		for ip, nhr := range dstmap {
			if p.Matches(&ip.p) && ip.i == f.index {
				dbgvnet.Adj.Logf("call addDelRouteNextHop delete %v prefix %v nexthop %v nhAdj %v from delAllRouteNextHops\n",
					f.index.Name(&m.Main), p.String(), id.a, x.adj)
				// for mpAdj, addDelRouteNextHop will take care of removing ip from dstmap as part of the cleanup and accounting?
				f.addDelRouteNextHop(m, p, id.a, nhr, true)
			}
		}
	}
}

// properly delete all nexthops in the adj
func (m *Main) delAllRouteNextHops(f *Fib, p *Prefix) {
	oldAdj, _ := f.Get(p)
	if oldAdj == ip.AdjNil || oldAdj == ip.AdjMiss || !m.IsMpAdj(oldAdj) {
		// Nothing to delete if AdjNil or AdjMiss
		// None mpAdj deletes are handled elsewhere, no concept of deleteAll there
		return
	}

	dbgvnet.Adj.Logf("from %v %v\n", f.index.Name(&m.Main), p.String())

	// find all nh from reachable that has p in its map; only need to look into length 32
	for _, r := range f.reachable[32] {
		r.delNhFromMatchingPrefix(m, f, p)
	}
	// find all nh from unreachable that has p in its map; only need to look into length 32
	for _, r := range f.unreachable[32] {
		r.delNhFromMatchingPrefix(m, f, p)
	}
}

func (m *Main) AddDelRouteNextHop(p *Prefix, nh *NextHop, isDel bool, isReplace bool) (err error) {
	f := m.fibBySi(nh.Si)
	oldAdj, _ := f.Get(p)

	if oldAdj != ip.AdjNil && oldAdj != ip.AdjMiss && !m.IsMpAdj(oldAdj) {
		// oldAdj is probably a glean or local, don't add or remove nh
		if vnet.AdjDebug {
			as := m.GetAdj(oldAdj)
			adjType := "no adjacency found at that adj index"
			if len(as) > 0 {
				adjType = as[0].LookupNextIndex.String()
			}
			if isDel {
				dbgvnet.Adj.Logf("isReplace %v: ignore deleting nh %v from prefix %v which has has non MpAdj %v of type %v\n",
					isReplace, nh.Address, p.String(), oldAdj, adjType)
			} else {
				dbgvnet.Adj.Logf("isReplace %v: ignore adding nh %v to prefix %v which has has non MpAdj %v of type %v\n",
					isReplace, nh.Address, p.String(), oldAdj, adjType)
			}
		}
		return
	}

	if isReplace { // Delete prefix and cleanup its adjacencies before add
		dbgvnet.Adj.Logf("Replace: delete %v and clean up old adjacency oldAdj %v\n", p.String(), oldAdj.String())
		// Do a proper cleanup and delete of old next hops
		m.delAllRouteNextHops(f, p)
	}
	if isDel {
		dbgvnet.Adj.Logf("call addDelRouteNextHop %v prefix %v oldAdj %v delete %v from AddDelRouteNextHop\n",
			f.index.Name(&m.Main), p.String(), oldAdj, nh.Address)
	} else {
		dbgvnet.Adj.Logf("call addDelRouteNextHop %v prefix %v oldAdj %v add nh %v from AddDelRouteNextHop\n",
			f.index.Name(&m.Main), p.String(), oldAdj, nh.Address)
	}
	return f.addDelRouteNextHop(m, p, nh.Address, nh, isDel)
}

//TBDIP6: TBD
func (f *Fib) addDelRouteNextHop(m *Main, p *Prefix, nha Address, nhr NextHopper, isDel bool) (err error) {
	var (
		nhAdj, oldAdj, newAdj ip.Adj
		ok                    bool
	)
	//if !isDel && nha.MatchesPrefix(p) && p.Address != AddressUint32(0) {
	if !isDel && nha.MatchesPrefix(p) && !p.Address.IsZero() {
		err = fmt.Errorf("fib.go addDelRouteNextHop add: prefix %s matches next-hop %s", p, &nha)
		return
	}

	nhf := m.fibByIndex(nhr.NextHopFibIndex(m), true)

	var reachable_via_prefix Prefix
	if r, np, found, bad := nhf.reachable.lookupReachable(m, nha); found || bad {
		if bad {
			err = &prefixError{s: "unreachable next-hop", p: *p}
			return
		}
		nhAdj = r.adj
		reachable_via_prefix = np
	} else {
		// not sure what's the purpose of recurse....
		// seems like it is trying to handle if the prefix that uses nha as next hop is in a different fib table, e.g. if f != nhf?
		// If they are the same, we could end up with multipe add or multiple del to same entry?
		const recurse = true
		err = nhf.addDelUnreachable(m, p, f, nha, nhr, isDel, recurse)
		{ //debug print
			if err != nil {
				fmt.Printf("fib.go addDelUnreachable err: recurse\n")
			}
		}
		return
	}

	oldAdj, ok = f.Get(p)
	if isDel && !ok {
		//debug print, flag but don't err if deleting
		//err = &prefixError{s: "unknown destination", p: *p}
		fmt.Printf("fib.go: deleteing %v unknown destination; maybe already deleted\n", p)
		return
	}

	if oldAdj == nhAdj && isDel {
		newAdj = ip.AdjNil
	} else if newAdj, ok = m.AddDelNextHop(oldAdj, nhAdj, nhr.NextHopWeight(), nhr, isDel); !ok { //for nhr NextHopper argument here, only AdjacencyFinalizer is used
		if true { //if this is a delete, don't error (which would cause panic later); just flag
			if !isDel {
				err = fmt.Errorf("fib.go addDelRouteNextHop add: %v %v, AddDelextHop !ok, oldAdj %v, nhAdj %v\n",
					f.index.Name(&m.Main), p.String(), oldAdj, nhAdj)
			} else {
				// This is legit.  Could get a message to remove a nexthop that is no longer the next hop of this prefix.
				// Example:  2 routes to a prefix, one via a rewrite next hop, one via glean.  Not consider a multipath, but it is effectively that.
				// vnet will choose one of the 2 to populate the TCAM depending on the order the add messages come in.  If the delete rewrite nexthop come in
				// and vnet had populated the glean as its nexthop, then AddDelNextHop will return !ok as the rewrite nhAdj is not there.
				fmt.Printf("fib.go addDelRouteNextHop delete: %v %v, AddDelextHop !ok, oldAdj %v, nhAdj %v, likely because %v was not its nh which is OK\n",
					f.index.Name(&m.Main), p.String(), oldAdj, nhAdj, nhAdj)
			}
		}
		return
	}

	if isDel {
		dbgvnet.Adj.Logf("delete: prefix %v,  oldAdj %v, newAdj %v\n", p.String(), oldAdj.String(), newAdj.String())
	} else {
		dbgvnet.Adj.Logf("add: prefix %v, oldAdj %v, newAdj %v\n", p.String(), oldAdj.String(), newAdj.String())
	}

	if oldAdj != newAdj {
		// oldAdj != newAdj means index changed because there is now more than 1 nexthop (multiplath)
		// or multipath members changed because of nexthop add/del

		isFibDel := isDel
		// if isDel, do not remove adjacency unless all members of the multipath adjacency have been removed
		// instead, update fib table with newAdj
		// when all member os the multipath are removed, newAdj will be ip.AdjNil
		if isFibDel && newAdj != ip.AdjNil {
			isFibDel = false
		}
		f.addDel(m, p, newAdj, isFibDel)
		nhf.setReachable(m, p, f, &reachable_via_prefix, nha, nhr, isDel)
	}
	return
}

// This is used by replaceWithLessSpecific and replaceWithMoreSpecific only
func (f *Fib) replaceNextHop(m *Main, p *Prefix, pf *Fib, fromNextHopAdj, toNextHopAdj ip.Adj, nha Address, r NextHopper) (err error) {
	if adj, ok := f.Get(p); !ok {
		//debug print instead of err; may be OK
		//err = &prefixError{s: "unknown destination", p: *p}
		fmt.Printf("fib.go: replaceNextHop, unknown destination, addr %v, nextHop %v, from-nha %v to-nha %v, namespace %s\n",
			p, nha, fromNextHopAdj, toNextHopAdj, f.index.Name(&m.Main))
	} else {

		dbgvnet.Adj.Logf("prefix %v from adj %v to adj %v, nha %v\n",
			p.String(), fromNextHopAdj, toNextHopAdj, nha)

		as := m.GetAdj(toNextHopAdj)
		// If replacement is glean (interface route) then next hop becomes unreachable.
		// Assume glean already exist so no need to explicity add here?
		isDel := len(as) == 1 && as[0].IsGlean()
		if isDel {
			dbgvnet.Adj.Logf("call addDelRouteNextHop prefix %v delete nh %v from replaceNextHop\n",
				p.String(), nha)
			err = pf.addDelRouteNextHop(m, p, nha, r, isDel)
			if err == nil {
				err = f.addDelUnreachable(m, p, pf, nha, r, !isDel, false)
			}
		} else {
			// Adjacencies in the toNextHopAj must be rewrites for ReplaceNextHop
			var newAdj ip.Adj
			if newAdj, err = m.ReplaceNextHop(adj, fromNextHopAdj, toNextHopAdj, r); err != nil {
				err = fmt.Errorf("replace next hop %v from-nha %v to-nha %v: %v", adj, fromNextHopAdj, toNextHopAdj, err)
			} else {
				m.callFibAddDelHooks(pf.index, p, newAdj, isDel)
			}
		}
	}
	if err != nil {
		panic(err)
	}
	return
}

func (f *Fib) deleteMatchingRoutes(m *Main, key *Prefix) {
	f.reachable.foreachMatchingPrefix(key, func(p *Prefix, r mapFibResult) {
		f.Del(m, p)
	})
}

//TBDIP6: PRG
//used for local or glean fib adjacencies
func (f *Fib) addDelReplace(m *Main, p *Prefix, r ip.Adj, isDel bool) {
	if vnet.AdjDebug {
		if isDel {
			dbgvnet.Adj.Logf("delete %v %v adj %v\n", f.index.Name(&m.Main), p.String(), r.String())
		} else {
			if m.IsMpAdj(r) {
				panic(fmt.Errorf("%v adding a multipath adj %v to glean or local fib %v!\n",
					f.index.Name(&m.Main), r.String(), p.String()))
			} else {
				dbgvnet.Adj.Logf("add %v %v adj %v\n", f.index.Name(&m.Main), p.String(), r.String())
			}
		}
	}

	oldAdj, _ := f.Get(p)
	// If oldAdj is a mpAdj, then need to do a cleanup and delete before adding the replacement adj
	if m.IsMpAdj(oldAdj) {
		// if add, clean up first by deleting oldAdj before adding
		// if delete, r argument is AdjNil or AdjMiss, so use oldAdj to delete here
		dbgvnet.Adj.Logf("%v %v %v: first delete old adjacency %v IsMpAdj %v\n",
			f.index.Name(&m.Main), p.String(), r.String(), oldAdj, m.IsMpAdj(oldAdj))
		// First delete all its next hops; this maintains the proper adjacency tracking
		// prefixes in fib, i.e. MapFib, are indexed by mapFibKey which has the mask applied
		// apply mask for the delAllRouteNextHops argument
		q := p.ApplyMask()
		m.delAllRouteNextHops(f, q)

		// This uses the original prefix
		if !isDel {
			// addDel new adjacency
			f.addDel(m, p, r, isDel)
		}
	} else {
		if oldAdj, ok := f.addDel(m, p, r, isDel); ok && oldAdj != ip.AdjNil && oldAdj != ip.AdjMiss && oldAdj != r {
			// oldAdj should not return as a mpAdj
			if m.IsMpAdj(oldAdj) {
				fmt.Printf("DEBUG: fib.go addDelReplace isDel %v %v %v adj %v:  addDel returned an oldAdj %v that is a mpAdj",
					isDel, f.index.Name(&m.Main), p.String(), r, oldAdj)
				return
			}
			if !m.IsAdjFree(oldAdj) {
				m.DelAdj(oldAdj)
			}
		}
	}
}

//TBDIP6: PRG check if inner calls have ip6 support
func (m *Main) addDelInterfaceAddressRoutes(ia ip.IfAddr, isDel bool) {
	ifa := m.GetIfAddr(ia)
	si := ifa.Si
	sw := m.Vnet.SwIf(si)
	hw := m.Vnet.SupHwIf(sw)
	fib := m.fibBySi(si)
	p := ToIp6Prefix(&ifa.Prefix)

	// Add interface's prefix as route tied to glean adjacency (arp for Ethernet).
	// Suppose interface has address 1.1.1.1/8; here we add 1.0.0.0/8 tied to glean adjacency.
	if p.Len < 128 {
		addDelAdj := ip.AdjNil
		if !isDel {
			ai, as := m.NewAdj(1)
			m.setInterfaceAdjacency(&as[0], si, ia)
			m.CallAdjAddHooks(ai)
			addDelAdj = ai
		}
		fib.addDelReplace(m, &p, addDelAdj, isDel)
		ifa.NeighborProbeAdj = addDelAdj
	}

	// Add 1.1.1.1/32 as a local address.
	{
		addDelAdj := ip.AdjNil
		if !isDel {
			ai, as := m.NewAdj(1)
			as[0].LookupNextIndex = ip.LookupNextLocal
			as[0].Index = uint32(ia)
			as[0].Si = si
			if hw != nil {
				as[0].SetMaxPacketSize(hw)
			}
			m.CallAdjAddHooks(ai)
			addDelAdj = ai
		}
		p.Len = 128
		fib.addDelReplace(m, &p, addDelAdj, isDel)
	}

	if isDel {
		fib.deleteMatchingRoutes(m, &p)
	}
}

//TBDIP6: PRG
func (m *Main) AddDelInterfaceAddress(si vnet.Si, addr *Prefix, isDel bool) (err error) {
	if !isDel {
		err = m.ForeachIfAddress(si, func(ia ip.IfAddr, ifa *ip.IfAddress) (err error) {
			p := ToIp6Prefix(&ifa.Prefix)
			if !p.IsEqual(addr) && (addr.Address.MatchesPrefix(&p) || p.Address.MatchesPrefix(addr)) {
				err = fmt.Errorf("%s: add %s conflicts with existing address %s", si.Name(m.Vnet), addr, &p)
			}
			return
		})
		if err != nil {
			return
		}
	}

	var (
		ia     ip.IfAddr
		exists bool
	)

	sw := m.Vnet.SwIf(si)
	isUp := sw.IsAdminUp()
	pa := addr.ToIpPrefix()

	// If interface is admin up, delete interface routes *before* removing address.
	if isUp && isDel {
		ia, exists = m.Main.IfAddrForPrefix(&pa, si)
		// For non-existing prefixes error will be signalled by AddDelInterfaceAddress below.
		if exists {
			// Question why this is done independently - rtnetlink should send
			// any routes it would like deleted.
			m.addDelInterfaceAddressRoutes(ia, isDel)
		}
	}

	// Delete interface address.  Return error if deleting non-existent address.
	if ia, exists, err = m.Main.AddDelInterfaceAddress(si, &pa, isDel); err != nil {
		return
	}

	// If interface is up add interface routes.
	if isUp && !isDel && !exists {
		m.addDelInterfaceAddressRoutes(ia, isDel)
	}

	// Do callbacks when new address is created or old one is deleted.
	if isDel || !exists {
		for i := range m.ifAddrAddDelHooks.hooks {
			m.ifAddrAddDelHooks.Get(i)(ia, isDel)
		}
	}

	return
}

func (m *Main) swIfAdminUpDown(v *vnet.Vnet, si vnet.Si, isUp bool) (err error) {
	m.validateDefaultFibForSi(si)
	m.ForeachIfAddress(si, func(ia ip.IfAddr, ifa *ip.IfAddress) (err error) {
		isDel := !isUp
		m.addDelInterfaceAddressRoutes(ia, isDel)
		return
	})
	return
}

func (f *Fib) Reset() {
	f.reachable.reset()
	f.unreachable.reset()
	f.mtrie.reset()
}

func (m *Main) FibReset(fi ip.FibIndex) {
	for i := range m.fibs {
		if i != int(fi) && m.fibs[i] != nil {
			m.fibs[i].reachable.clean(fi)
			m.fibs[i].unreachable.clean(fi)
		}
	}

	f := m.fibByIndex(fi, true)
	f.Reset()
}

/* end: of copy-paste code */

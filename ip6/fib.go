// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ip6

import (
	"github.com/platinasystems/elib/dep"
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/internal/dbgvnet"
	"github.com/platinasystems/vnet/ip"

	"fmt"
	"net"
	"runtime"
	"sync"
)

type Prefix struct {
	Address
	Len uint32
}

type RouteType uint8

func (t RouteType) String() string {
	switch t {
	case CONN:
		return "connected"
	case VIA:
		return "via_route"
	case GLEAN:
		return "glean"
	case LOCAL:
		return "local"
	case PUNT:
		return "punt"
	case DROP:
		return "drop"
	default:
		return "unspecified"

	}
}

// this list of const is in order of perference for installing route
const (
	// drops at hardware (blackhole)
	DROP RouteType = iota
	// punts to Linux
	PUNT
	// neighbor
	CONN
	// has via next hop(s)
	VIA
	// glean
	GLEAN
	// interface addr of vnet recognized interface
	LOCAL
)

type ipFib ip.Fib

var LinklocalUnicast = net.IPNet{
	IP:   net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	Mask: net.IPMask{0xff, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
}

type FibResult struct {
	m         *Main
	Adj       ip.Adj
	Installed bool
	Prefix    net.IPNet
	Type      RouteType
	Nhs       ip.NextHopVec       // nexthops for Address
	usedBy    mapFibResultNextHop // used to track prefixes that uses Prefix.Address as its nexthop
}

type FibResultVec []FibResult

// Maps for prefixes for /0 through /32; key in network byte order.
type MapFib [1 + 128]map[string]FibResultVec

type NextHop struct {
	Address net.IP
	Si      vnet.Si
	Weight  ip.NextHopWeight
}

func (n *NextHop) NextHopWeight() ip.NextHopWeight     { return n.Weight }
func (n *NextHop) NextHopFibIndex(m *Main) ip.FibIndex { return m.FibIndexForSi(n.Si) }
func (n *NextHop) FinalizeAdjacency(a *ip.Adjacency)   {}

type NextHopper interface {
	ip.AdjacencyFinalizer
	NextHopFibIndex(m *Main) ip.FibIndex
	NextHopWeight() ip.NextHopWeight
}

type nhUsage struct {
	referenceCount uint32
	nhr            NextHop
}

type ipre struct {
	p string // stringer output of net.IPNet
	i ip.FibIndex
}

// idst is the destination or nh address and namespace
// ipre is the prefix that has idst as its nh
//type mapFibResultNextHop map[idst]map[ipre]NextHop
type mapFibResultNextHop map[ipre]nhUsage

//v1 wrapper code in ip
//type FibResultVec []ip.FibResult

func (m *Main) setInterfaceAdjacency(a *ip.Adjacency, si vnet.Si) {
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
	}

	a.LookupNextIndex = next

	a.Si = si

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

type Fib struct {
	index ip.FibIndex
	Name  ip.FibName

	// reachable and unreachable IP address from neighbor messages
	// these have 1 entry per prefix
	reachable, unreachable MapFib

	// routes and their nexthops
	// these can have more than 1 entry per prefix
	routeFib     MapFib //i.e. via nexthop
	local, glean MapFib
	punt, drop   MapFib //punt goes to linux, drop drops at hardware
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

func makeKey(p *net.IPNet) (l uint32, k string) {
	size, _ := p.Mask.Size()
	l = uint32(size)
	k = p.IP.String()
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

func (m *MapFib) validateLen(l uint32) {
	if m[l] == nil {
		m[l] = make(map[string]FibResultVec)
	}
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

type FibAddDelHook func(i ip.FibIndex, p *Prefix, r ip.Adj, isDel bool)
type IfAddrAddDelHook func(ia ip.IfAddr, isDel bool)

func IPNetToV6Prefix(ipn net.IPNet) (p Prefix) {
	l, _ := ipn.Mask.Size()
	p.Len = uint32(l)
	// p.Address has a length already, so ok to just copy
	copy(p.Address[:], ipn.IP[:])
	return
}

func (m *fibMain) RegisterFibAddDelHook(f FibAddDelHook, dep ...*dep.Dep) {
	m.fibAddDelHooks.Add(f, dep...)
}

func (m *fibMain) callFibAddDelHooks(fi ip.FibIndex, p *net.IPNet, r ip.Adj, isDel bool) {
	q := IPNetToV6Prefix(*p)
	for i := range m.fibAddDelHooks.hooks {
		m.fibAddDelHooks.Get(i)(fi, &q, r, isDel)
	}
}

/* progress tracking markers: DONE/OK => done, TBD or unmarked => revisit, PRG/MOD - in-progress,
   DEL/del - remove (changes are done appropriately/elsewhere)
   NOTE: remove all commented out code after integration with FDB changes
*/
/* begin: copy-paste code for new ip4/fib.go */
func (m *MapFib) SetConn(ma *Main, p *net.IPNet, adj ip.Adj, si vnet.Si) (oldAdj ip.Adj, result *FibResult, ok bool) {
	var nhs ip.NextHopVec
	nh := ip.NextHop{Si: si}
	nhs = append(nhs, nh)
	return m.Set(ma, p, adj, nhs, CONN)
}
func (m *MapFib) UnsetConn(p *net.IPNet, si vnet.Si) (oldAdj ip.Adj, ok bool) {
	var nhs ip.NextHopVec
	nh := ip.NextHop{Si: si}
	nhs = append(nhs, nh)
	return m.Unset(p, nhs)
}

func (m *MapFib) Set(ma *Main, p *net.IPNet, newAdj ip.Adj, nhs ip.NextHopVec, rt RouteType) (oldAdj ip.Adj, result *FibResult, ok bool) {
	l, k := makeKey(p)
	m.validateLen(l)
	var (
		rs FibResultVec
		r  FibResult
		ri int
	)
	oldAdj = ip.AdjNil

	// Allow identical prefix/nhs to be added as new instead of just update adj
	if rs, ok = m[l][k]; ok && false {
		// if a result with nhs already exists, update adj and done
		if r, ri, ok = rs.GetByNhs(nhs); ok {
			oldAdj = r.Adj
			m[l][k][ri].Adj = newAdj
			result = &m[l][k][ri]
			return
		}
	}
	ok = true
	// r is a blank RouterFibResult, fill it in
	r.m = ma
	r.Adj = newAdj
	r.Prefix = *p
	r.Nhs = nhs
	r.Type = rt
	// add r to end of RouterFibResultVec
	m[l][k] = append(m[l][k], r)
	result = &m[l][k][len(m[l][k])-1]
	return
}

func (m *MapFib) Unset(p *net.IPNet, nhs ip.NextHopVec) (oldAdj ip.Adj, ok bool) {
	dbgvnet.Adj.Log(p, nhs)
	l, k := makeKey(p)
	m.validateLen(l)
	var (
		rs FibResultVec
		r  FibResult
		ri int
	)
	if rs, ok = m[l][k]; ok {
		dbgvnet.Adj.Log("found rs")
		if r, ri, ok = rs.GetByNhs(nhs); ok {
			dbgvnet.Adj.Log("found nhs")
			oldAdj = r.Adj
			copy(rs[ri:], rs[ri+1:])
			rs[len(rs)-1] = FibResult{}
			rs = rs[:len(rs)-1]
			if len(rs) == 0 {
				delete(m[l], k)
			} else {
				m[l][k] = rs
			}
			dbgvnet.Adj.Log("done")
			return
		}
	}
	oldAdj = ip.AdjNil
	dbgvnet.Adj.Log("DEBUG", p, nhs, "not found")
	return
}

func (m *Main) fibByIndex(i ip.FibIndex, create bool) (f *Fib) {
	m.fibs.Validate(uint(i))
	if create && m.fibs[i] == nil {
		//TBDIP6: fields are not exported; getter method to return new
		//obj
		m.fibs[i] = &Fib{
			index: i,
			Name: ip.FibName{
				M: &m.Main,
				I: i,
			},
		}
		//m.fibs[i] = ip.GetNewFib(i, &m.Main)
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
	//i := m.FibIndexForSi(si)
	i := m.ValidateFibIndexForSi(si)
	return m.fibByIndex(i, true)
}

func (m *Main) validateDefaultFibForSi(si vnet.Si) {
	i := m.ValidateFibIndexForSi(si)
	m.fibByIndex(i, true)
}

// This updates the FibResult's usedBy map that prefix p is or is no longer using r as its nexthop
func (r *FibResult) addDelUsedBy(m *Main, pf *Fib, p *net.IPNet, nhr NextHop, isDel bool) {
	ip := ipre{p: p.String(), i: pf.index}
	nhu, found := r.usedBy[ip]

	if isDel {
		if found {
			nhu.referenceCount--
			r.usedBy[ip] = nhu
			if nhu.referenceCount == 0 {
				delete(r.usedBy, ip)
			}
		} else {
			dbgvnet.Adj.Log("delete, but", p, "is not used by", nhr.Address)
		}
	} else {
		if r.usedBy == nil {
			r.usedBy = make(map[ipre]nhUsage)
		}
		if found {
			nhu.referenceCount++
		} else {
			nhu = nhUsage{
				referenceCount: 1,
				nhr:            nhr,
			}
		}
		r.usedBy[ip] = nhu
	}
}

// setReachable and setUnreachable updates UsedBy map of which prefix uses the reachable/unreachable as nexthop
// create and delete of FibResult entry for reachable is done at neighbor resolution (addDelRoute) as that's absolute
func (f *Fib) setReachable(m *Main, p *net.IPNet, pf *Fib, nhr NextHop, isDel bool) {
	nhp := net.IPNet{
		IP:   nhr.Address,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}

	if _, r, found := f.GetReachable(&nhp, nhr.Si); found {
		r.addDelUsedBy(m, pf, p, nhr, isDel)
		dbgvnet.Adj.Logf("%v %v prefix %v via %v, new result\n%v",
			vnet.IsDel(isDel), f.Name, p, nhr.Address, r)
		return
	}
	dbgvnet.Adj.Logf("DEBUG did not find %v in reachable\n", nhr.Address)
}

// create and delete of FibResult entry depends on whether any ViaRoute uses a unresolved as its nexthop, and is done here
func (f *Fib) setUnreachable(m *Main, p *net.IPNet, pf *Fib, nhr NextHop, isDel bool) {
	nhp := net.IPNet{
		IP:   nhr.Address,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}
	var (
		found bool
		r     *FibResult
	)

	if _, r, found = f.GetUnreachable(&nhp, nhr.Si); !found && !isDel {
		_, r, found = f.unreachable.SetConn(m, &nhp, ip.AdjMiss, nhr.Si)
	}

	if found {
		r.addDelUsedBy(m, pf, p, nhr, isDel)
		if len(r.usedBy) == 0 {
			f.unreachable.UnsetConn(&nhp, nhr.Si)
		}
		dbgvnet.Adj.Logf("%v %v prefix %v via %v, updated result\n%v",
			vnet.IsDel(isDel), f.Name, p, nhr.Address, r)
		return
	}
	if !found && isDel {
		dbgvnet.Adj.Logf("DEBUG %v did not find %v in unreachable\n", vnet.IsDel(isDel), nhr.Address)
		return
	}
}

// ur is a mapFibResult from unreachable that we will move to reachable here
func (ur *FibResult) makeReachable(m *Main, f *Fib, adj ip.Adj) {
	a := ur.Prefix.IP
	dbgvnet.Adj.Log("unreachable before")
	dbgvnet.AdjPlain.Log(ur)
	for dp, nhu := range ur.usedBy {
		g := m.fibByIndex(dp.i, false)
		const isDel = false
		dbgvnet.Adj.Logf("call addDelRouteNextHop prefix %v add nh %v from makeReachable\n",
			dp.p, a)
		// add adj to nexthop
		var (
			p   *net.IPNet
			err error
		)
		if _, p, err = net.ParseCIDR(dp.p); err != nil {
			fmt.Printf("DEBUG makeReachable: invalid prefix index %v\n", dp.p)
			panic(err)
		}
		g.addDelRouteNextHop(m, p, a, NextHopper(&nhu.nhr), adj, isDel)
		// update p in the reachable's UsedBy map
		f.setReachable(m, p, f, nhu.nhr, isDel)

		// decrement/delete from unreachable's UsedBy map
		nhu.referenceCount--
		ur.usedBy[dp] = nhu
		if nhu.referenceCount == 0 {
			delete(ur.usedBy, dp)
		}
	}
	// if no fib using ur as unreachable next hop, then delete ur
	if len(ur.usedBy) == 0 {
		p := ur.Prefix
		f.unreachable.UnsetConn(&p, ur.Nhs[0].Si)
	}
	dbgvnet.Adj.Log("unreachable after", ur)
	dbgvnet.AdjPlain.Log(ur)
}

// r is a mapFibResult from reachable that we will move to unreachable here
func (r *FibResult) makeUnreachable(m *Main, f *Fib) {
	a := r.Prefix.IP
	adj := r.Adj
	for dp, nh := range r.usedBy {
		g := m.fibByIndex(dp.i, false)
		const isDel = true
		dbgvnet.Adj.Logf("call addDelRouteNextHop prefix %v add nh %v from makeUnreachable\n",
			dp.p, a)
		var (
			p   *net.IPNet
			err error
		)
		if _, p, err = net.ParseCIDR(dp.p); err != nil {
			fmt.Printf("DEBUG makeUnreachable: invalid prefix index %v\n", dp.p)
			panic(err)
		}
		// remove adj from nexthop
		g.addDelRouteNextHop(m, p, a, NextHopper(&nh.nhr), adj, isDel)
		// update p in the unreachable's UsedBy map
		f.setUnreachable(m, p, f, nh.nhr, !isDel)

		// decrement/delete from reachable's UsedBy map
		nh.referenceCount--
		r.usedBy[dp] = nh
		if nh.referenceCount == 0 {
			delete(r.usedBy, dp)
		}
	}

}

func (f *Fib) addDelReachable(m *Main, r *FibResult, isDel bool) {
	p := r.Prefix
	a := r.Adj
	si := r.Nhs[0].Si

	if isDel {
		dbgvnet.Adj.Logf("delete: %v %v adj %v makeUnreachable\n%v",
			f.Name, &p, a, r)
		r.makeUnreachable(m, f)
	} else {
		if _, ur, found := f.GetUnreachable(&p, si); found {
			// update prefixes that use a now that a is reachable
			ur.makeReachable(m, f, a)
		}
		// if not found, then first time nh appears as a neighbor; no UsedBy map to update
	}
	dbgvnet.Adj.Logf("%v: %v reachable new reachable:\n%v",
		vnet.IsDel(isDel), f.Name, r)
}

func (f *Fib) GetInstalled(p *net.IPNet) (result *FibResult, ok bool) {
	// check drop first
	if result, ok = f.drop.getInstalled(p); ok {
		return
	}
	// check reachable first
	if result, ok = f.reachable.getInstalled(p); ok {
		return
	}
	// check via Routes
	if result, ok = f.routeFib.getInstalled(p); ok {
		return
	}
	// check glean
	if result, ok = f.glean.getInstalled(p); ok {
		return
	}
	// check local
	if result, ok = f.local.getInstalled(p); ok {
		return
	}
	// check punt
	if result, ok = f.punt.getInstalled(p); ok {
		return
	}
	return
}

func (x *MapFib) getInstalled(p *net.IPNet) (result *FibResult, ok bool) {
	var (
		rs FibResultVec
	)
	l, k := makeKey(p)
	x.validateLen(l)
	if rs, ok = x[l][k]; ok {
		// only 1 should be installed, and should be the 1st one
		// for debug, check them all
		for i, r := range rs {
			if r.Installed {
				result = &x[l][k][i]
				if i != 0 {
					dbgvnet.Adj.Logf("DEBUG installed is the %vth entry in vector instead of 0th\n", i)
				}
				return
			}
		}
	}
	ok = false
	return
}

func (x *MapFib) getFirstUninstalled(p *net.IPNet, checkAdjValid bool) (result *FibResult, ok bool) {
	var (
		rs FibResultVec
	)
	l, k := makeKey(p)
	x.validateLen(l)
	if rs, ok = x[l][k]; ok {
		// only 1 should be installed, and should be the 1st one
		// for debug, check them all
		for i, r := range rs {
			if !r.Installed && !(checkAdjValid && !(r.Adj != ip.AdjNil && r.Adj != ip.AdjMiss)) {
				result = &x[l][k][i]
				return
			}
		}
	}
	ok = false
	return
}

func (x *MapFib) GetBySi(p *net.IPNet, si vnet.Si) (a ip.Adj, result *FibResult, ok bool) {
	var (
		rs FibResultVec
		r  FibResult
		ri int
	)
	l, k := makeKey(p)
	x.validateLen(l)
	if rs, ok = x[l][k]; ok {
		if r, ri, ok = rs.GetBySi(si); ok {
			a = r.Adj
			result = &x[l][k][ri]
		}
	}
	return
}

func (rs *FibResultVec) ForeachMatchingNhAddress(nha net.IP, fn func(r *FibResult, nh *ip.NextHop)) {
	for ri, r := range *rs {
		for i, nh := range r.Nhs {
			if nh.Address.Equal(nha) {
				fn(&r, &nh)
				r.Nhs[i] = nh
				(*rs)[ri] = r
			}
		}
	}
}

func (x *MapFib) GetByNhs(p *net.IPNet, nhs ip.NextHopVec) (a ip.Adj, result *FibResult, ok bool) {
	var (
		rs FibResultVec
		r  FibResult
		ri int
	)
	l, k := makeKey(p)
	x.validateLen(l)
	if rs, ok = x[l][k]; ok {
		if r, ri, ok = rs.GetByNhs(nhs); ok {
			a = r.Adj
			result = &x[l][k][ri]
		}
	}
	return
}

// returns first match
func (rs FibResultVec) GetByNhs(nhs ip.NextHopVec) (r FibResult, ri int, ok bool) {
	// nhs = nil are match also
	for i, _ := range rs {
		if rs[i].Nhs == nil && nhs == nil {
			r = rs[i]
			ri = i
			ok = true
			return
		}
		if rs[i].Nhs == nil || nhs == nil {
			continue
		}
		if rs[i].Nhs.Match(nhs) {
			r = rs[i]
			ri = i
			ok = true
			return
		}
	}
	return
}

// This returns 1st FibResult with a nh si that match; used to look up local and glean
func (rs FibResultVec) GetBySi(si vnet.Si) (r FibResult, ri int, ok bool) {
	for i, _ := range rs {
		for _, nh := range rs[i].Nhs {
			if nh.Si == si {
				r = rs[i]
				ri = i
				ok = true
				return
			}
		}
	}
	return
}

func (f *Fib) GetReachable(p *net.IPNet, si vnet.Si) (a ip.Adj, result *FibResult, ok bool) {
	return f.reachable.GetBySi(p, si)
}

func (f *Fib) GetUnreachable(p *net.IPNet, si vnet.Si) (a ip.Adj, result *FibResult, ok bool) {
	return f.unreachable.GetBySi(p, si)
}

func (f *Fib) GetFib(p *net.IPNet, nhs ip.NextHopVec) (a ip.Adj, result *FibResult, ok bool) {
	return f.routeFib.GetByNhs(p, nhs)
}

func (f *Fib) GetLocal(p *net.IPNet, si vnet.Si) (a ip.Adj, result *FibResult, ok bool) {
	return f.local.GetBySi(p, si)
}

func (f *Fib) GetGlean(p *net.IPNet, si vnet.Si) (a ip.Adj, result *FibResult, ok bool) {
	return f.glean.GetBySi(p, si)
}

func (f *Fib) GetPunt(p *net.IPNet) (result *FibResult, ok bool) {
	var (
		rs FibResultVec
	)
	l, k := makeKey(p)
	f.punt.validateLen(l)
	if rs, ok = f.punt[l][k]; ok {
		if len(rs) > 0 {
			ok = true
			// they all have same prefix and adjPunt so just return the first one
			result = &f.punt[l][k][0]
		}
	}
	return
}

func (f *Fib) GetDrop(p *net.IPNet) (result *FibResult, ok bool) {
	var (
		rs FibResultVec
	)
	l, k := makeKey(p)
	f.drop.validateLen(l)
	if rs, ok = f.drop[l][k]; ok {
		if len(rs) > 0 {
			ok = true
			// they all have same prefix and adjDrop so just return the first one
			result = &f.drop[l][k][0]
		}
	}
	return
}

/* v2 addFib() from ip4/fib.go
 */
func (f *Fib) addFib(m *Main, r *FibResult) (installed bool) {
	if r == nil {
		panic(fmt.Errorf("addFib got nil FibResult pointer for argument"))
	}
	dbgvnet.Adj.Log(f.Name)
	dbgvnet.AdjPlain.Log(r)
	p := r.Prefix
	// check if there is already an adj installed with same prefix
	oldr, found := f.GetInstalled(&p)

	if !found { // install new
		m.callFibAddDelHooks(f.index, &p, r.Adj, false)
		installed = true
		r.Installed = installed
		dbgvnet.Adj.Log("installed new")
		return
	}

	// something else had previously been installed
	// install only if oldr is not more preferred
	switch r.Type {
	case DROP:
		// aways install
	case PUNT:
		if oldr.Type < PUNT {
			return
		}
	case CONN:
		if oldr.Type < CONN {
			return
		}
	case VIA:
		if oldr.Type < VIA {
			return
		}
	case GLEAN:
		if oldr.Type < GLEAN {
			return
		}
	case LOCAL:
		if oldr.Type < LOCAL {
			return
		}
	default:
		dbgvnet.Adj.Log("DEBUG unspecifed route type for prefix", &r.Prefix)
		return
	}

	dbgvnet.Adj.Log("call FibAddDelHook", &p, "adj", r.Adj)
	// AddDelHook replaced any previous adj with new on
	m.callFibAddDelHooks(f.index, &p, r.Adj, false)
	oldr.Installed = false
	installed = true
	r.Installed = installed
	dbgvnet.Adj.Log("replaced existing")
	return
}

func (f *Fib) delFib(m *Main, r *FibResult) {
	if r == nil {
		panic(fmt.Errorf("delFib got nil FibResult pointer for argument"))
	}
	dbgvnet.Adj.Log(f.Name)
	dbgvnet.AdjPlain.Log(r)
	if !r.Installed {
		dbgvnet.Adj.Logf("prefix %v of type %v was not installed to begin with\n",
			r.Prefix, r.Type)
		return
	}

	// check if there is another less preferred route that should be installed in after
	// check before mark uninstall so we don't get prefix p back as the next preferred
	p := r.Prefix
	var (
		newr  *FibResult
		found bool
	)
	checkAdjValid := true
	if newr, found = f.drop.getFirstUninstalled(&p, checkAdjValid); found {
	} else if newr, found = f.punt.getFirstUninstalled(&p, checkAdjValid); found {
	} else if newr, found = f.reachable.getFirstUninstalled(&p, checkAdjValid); found {
	} else if newr, found = f.routeFib.getFirstUninstalled(&p, checkAdjValid); found {
	} else if newr, found = f.glean.getFirstUninstalled(&p, checkAdjValid); found {
	} else if newr, found = f.local.getFirstUninstalled(&p, checkAdjValid); found {
	}

	// uninstall old
	dbgvnet.Adj.Log("call FibAddDelHook", &p, "adj", r.Adj)
	m.callFibAddDelHooks(f.index, &p, r.Adj, true)
	r.Installed = false
	if found {
		dbgvnet.Adj.Logf("call f.addFib to replace with %v\n", newr)
		// install replacement
		f.addFib(m, newr)
	}
}

/* v1 wrapper to replace addFib:
 * calls addDelHooks thats presently called by addFib
 */
func (m *Main) addFibHelper(f *ip.Fib, r *ip.FibResult) {
	oldr, isNew := f.AddFib(r)
	p := r.Prefix
	//case 1: addFib() new; case 2: replace Fib
	if isNew {
		m.callFibAddDelHooks(f.GetFibIndex(), &p, r.Adj, false)
	} else {
		m.callFibAddDelHooks(f.GetFibIndex(), &p, r.Adj, false)
		oldr.Installed = false
	}
	r.Installed = true
}

/* v1 wrapper to replace delFib:
 * calls addDelHooks thats presently called by delFib
 */
func (m *Main) delFibHelper(f *ip.Fib, r *ip.FibResult) {
	p := r.Prefix
	newr, found := f.DelFib(r)
	m.callFibAddDelHooks(f.GetFibIndex(), &p, r.Adj, true)
	r.Installed = false
	if found {
		m.addFibHelper(f, newr)
	}
}

func printStack() {
	var buf [4096]byte
	n := runtime.Stack(buf[:], false)
	dbgvnet.Adj.Logf("%s", buf[:n])
}

func recoverAddDelRoute() {
	defer printStack()
	if r := recover(); r != nil {
		fmt.Println("recovered from ", r)
	}
}

// Used by neighbor message to add/del route, e.g. from succesfull arp, or install AdjPunt
// Tied to AddDelRoute() and called directly from ethernet/neighbor.go and a few other places
// The adjacency is created/updated elsewhere and the index passed in
func (m *Main) addDelRoute(p *net.IPNet, fi ip.FibIndex, adj ip.Adj, isDel bool) (oldAdj ip.Adj, err error) {
	dbgvnet.Adj.Logf("enter fi %v  isDel %v prefix %v adj %v", fi, vnet.IsDel(isDel), p, adj)
	defer recoverAddDelRoute()
	createFib := !isDel
	f := m.fibByIndex(fi, createFib)
	var (
		r         *FibResult
		ok, found bool
	)

	dbgvnet.Adj.Logf("isDel %v prefix %v adj %v", vnet.IsDel(isDel), p, adj)

	if connected, si := adj.IsConnectedRoute(&m.Main); connected { // arped neighbor
		oldAdj, r, found = f.GetReachable(p, si)
		dbgvnet.Adj.Logf("found %v, adj %v->%v",
			found, oldAdj, adj)
		if isDel && found {
			//TBDIP6: call helper
			//m.delFibHelper(f, r)
			if r.Installed {
				f.delFib(m, r)
			}
			//f.delFib(m, r)
			//f.AddDelReachable(&m.Main, r, isDel)
			//TBDIP6:
			//oldAdj, ok = f.UnsetConnByType(p, si, ip.REACHABLE_FIB)
			f.addDelReachable(m, r, isDel)
			oldAdj, ok = f.reachable.UnsetConn(p, si)
			// neighbor.go takes care of DelAdj so no need to do so here on delete
		}
		if !isDel {
			if found {
				if oldAdj == adj {
					// re-add the fib to hardware as rewrite likely has been updated
					dbgvnet.Adj.Log("update rewrite of adj", adj)
					//TBDIP6: call helper
					//m.addFibHelper(f, r)
					f.addFib(m, r)
					return
				} else {
					// can only have 1 neighbor per prefix/si, so unset any previous
					// should not hit this as ethernet/neighbor.go does a GetReachable first to obtain adj
					dbgvnet.Adj.Logf("DEBUG DEBUG delete previous adj %v before adding new adj %v\n", oldAdj, adj)
					//TBDIP6:
					//oldAdj, ok = f.UnsetConnByType(p, si, ip.REACHABLE_FIB)
					oldAdj, ok = f.reachable.UnsetConn(p, si)
				}
			}
			// create a new reachable entry
			// Set before addFib before addDelReachable in that order
			//TBDIP6:
			//_, r, _ := f.SetConnByType(&m.Main, p, adj, si, ip.REACHABLE_FIB)
			_, r, _ := f.reachable.SetConn(m, p, adj, si)
			//TBDIP6: call helper
			//m.addFibHelper(f, r)
			//f.AddDelReachable(&m.Main, r, isDel)
			f.addFib(m, r)
			f.addDelReachable(m, r, isDel)
			ok = true
		}
		if !ok {
			dbgvnet.Adj.Log("DEBUG", vnet.IsDel(isDel), p, "connected route not ok")
			err = fmt.Errorf("%v %v connected route not ok\n", vnet.IsDel(isDel), p)
		}
		return
	}
	if adj == ip.AdjPunt {
		//TBDIP6:
		//r, found = f.GetInstalledByType(p, ip.PUNT_FIB)
		r, found = f.punt.getInstalled(p)
		if isDel && found {
			//TBDIP6: call helper
			//m.delFibHelper(f, r)
			f.delFib(m, r)
			//TBDIP6:
			//oldAdj, ok = f.UnsetByType(p, ip.NextHopVec{}, ip.PUNT_FIB)
			oldAdj, ok = f.punt.Unset(p, ip.NextHopVec{})
		}
		if !isDel {
			//TBDIP6:
			//oldAdj, r, ok = f.SetByType(&m.Main, p, adj, ip.NextHopVec{}, ip.PUNT_FIB)
			oldAdj, r, ok = f.punt.Set(m, p, adj, ip.NextHopVec{}, PUNT)
			//TBDIP6: call helper
			//m.addFibHelper(f, r)
			f.addFib(m, r)
		}
		if !ok {
			dbgvnet.Adj.Log("DEBUG", vnet.IsDel(isDel), p, "punt not ok")
			err = fmt.Errorf("%v %v punt not ok\n", vnet.IsDel(isDel), &p)
		}
		return
	}

	if adj.IsGlean(&m.Main) {
		dbgvnet.Adj.Log("DEBUG should not be used for glean adj", adj)
	}
	if adj.IsLocal(&m.Main) {
		dbgvnet.Adj.Log("DEBUG should not be used for local adj", adj)
	}
	if adj.IsViaRoute(&m.Main) {
		dbgvnet.Adj.Log("DEBUG should not be used for nexthop adj", adj)
	}

	err = fmt.Errorf("%v %v adj %v not connected route or punt\n", vnet.IsDel(isDel), p, adj)
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

func (m *Main) updateAdjAndUsedBy(f *Fib, p *net.IPNet, nhs *ip.NextHopVec, isDel bool) {
	dbgvnet.Adj.Log(f.Name, p, vnet.IsDel(isDel))
	for nhi, nh := range *nhs {
		var (
			adj   ip.Adj
			found bool
		)
		nhp := net.IPNet{
			IP:   nh.Address,
			Mask: net.IPv4Mask(255, 255, 255, 255),
		}
		nhr := NextHop{
			Address: nh.Address,
			Si:      nh.Si,
			Weight:  nh.Weight,
		}
		nhf := m.fibByIndex(nh.NextHopFibIndex(&m.Main), true) // fib/namesapce that nh.Si belongs to

		adj, _, found = nhf.GetReachable(&nhp, nh.Si) // adj = 0(AdjMiss) if not found

		// if add, need to update the adj as it will not have been filled in yet
		if !isDel {
			(*nhs)[nhi].Adj = adj

			if adj == ip.AdjMiss {
				// adding a punt to arp
				//(*nhs)[nhi].Adj = ip.AdjPunt
			}
		}

		if found {
			// if nh is reachable
			// update reachable map by adding p to nhp's usedBy map
			nhf.setReachable(m, p, f, nhr, isDel)
		} else {
			// if nh is not reachable
			// update unreachable map, adding p to nhp's usedBy map
			f.setUnreachable(m, p, f, nhr, isDel)
		}
	}
}

// NextHops comes as a vector
func (m *Main) AddDelRouteNextHops(fibIndex ip.FibIndex, p *net.IPNet, nhs ip.NextHopVec, isDel bool, isReplace bool) (err error) {
	f := m.fibByIndex(fibIndex, true)
	dbgvnet.Adj.Logf("%v %v %v isReplace %v, nhs: \n%v\n",
		vnet.IsDel(isDel), f.Name, p, isReplace, nhs.ListNhs(&m.Main))
	var (
		r      *FibResult
		ok     bool
		oldAdj ip.Adj
	)
	if isDel {
		if oldAdj, r, ok = f.GetFib(p, nhs); ok {
			f.delFib(m, r) // remove from fib
		} else {
			dbgvnet.Adj.Log("DEBUG delete, cannot find", f.Name, p)
			err = fmt.Errorf("AddDelRouteNextHops delete, cannot find %v %v\n", f.Name, &p)
		}
	}
	if isReplace {
		if r, ok = f.routeFib.getInstalled(p); ok {
			f.delFib(m, r)
		} else if r, ok = f.routeFib.getFirstUninstalled(p, false); ok {
			// no need to remove from fib since not installed
		}
	}
	if (isDel || isReplace) && ok {
		// make a copy of contents of r.Nhs
		nhs_old := r.Nhs
		// update nhs_old to update usesBy map of nexthops that used p
		m.updateAdjAndUsedBy(f, p, &nhs_old, true)
		oldAdj, ok = f.routeFib.Unset(p, r.Nhs)
		m.DelNextHopsAdj(oldAdj)
	}
	if !isDel {
		// update the adj and usedBy map for nhs
		m.updateAdjAndUsedBy(f, p, &nhs, isDel)
		if len(nhs) == 0 {
			dbgvnet.Adj.Log("DEBUG ignore add via route", p, "with no next hops")
		}
		if newAdj, ok := m.AddNextHopsAdj(nhs); ok {
			oldAdj, r, ok = f.routeFib.Set(m, p, newAdj, nhs, VIA)
			l, k := makeKey(p)
			f.routeFib.validateLen(l)
			if len(f.routeFib[l][k]) == 1 && r.Adj != ip.AdjNil {
				// first via route for prefix p; try installing it
				f.addFib(m, r) // add
			}
		} else {
			dbgvnet.Adj.Log("DEBUG failed to get adj for", f.Name, p)
		}
	}
	return
}

// modified for legacy netlink and ip/cli use, where nexthop were added 1 at a time instead of a vector at at time
func (m *Main) AddDelRouteNextHop(p *net.IPNet, nh *NextHop, isDel bool, isReplace bool) (err error) {
	var nhs ip.NextHopVec
	new_nh := ip.NextHop{
		Address: nh.Address,
		Si:      nh.Si,
	}
	new_nh.Weight = nh.Weight
	f := m.fibBySi(nh.Si)
	nhs = append(nhs, new_nh)
	return m.AddDelRouteNextHops(f.index, p, nhs, isDel, isReplace)
}

// Mark a nha as reachable(add) or unreachable(del) for ALL routeFibResults in p that has nha as a nexthop
// Update each matching routeFibResult with a newAdj
// Note this doesn't actually remove the nexthop from Prefix; that's done via AddDelRouteNextHops when Linux explicitly deletes or replaces a via route
func (f *Fib) addDelRouteNextHop(m *Main, p *net.IPNet, nhIP net.IP, nhr NextHopper, nhAdj ip.Adj, isDel bool) (err error) {
	var (
		oldAdj, newAdj ip.Adj
		ok             bool
		rs             FibResultVec
	)

	l, k := makeKey(p)
	f.routeFib.validateLen(l)
	if rs, ok = f.routeFib[l][k]; !ok {
		dbgvnet.Adj.Log("DEBUG DEBUG", f.Name, p, "not found")
		err = fmt.Errorf("%v %v not found\n", f.Name, &p)
		return
	}
	newAdj = ip.AdjNil

	// update rs with nhAdj if reachable (add) or a new arp adj if unreachale (del); detele oldAj
	rs.ForeachMatchingNhAddress(nhIP, func(r *FibResult, nh *ip.NextHop) {
		if isDel {
			//ai, as := m.NewAdj(1)
			//m.setArpAdjacency(&as[0], nh.Si)
			//nh.Adj = ai
			nh.Adj = ip.AdjMiss
		} else {
			nh.Adj = nhAdj
		}
	})

	// Do this as separate ForEach because r.Nhs will not have been updated until the ForeachMatchingNhAddress completed
	// update with newAdj and addFib
	rs.ForeachMatchingNhAddress(nhIP, func(r *FibResult, nh *ip.NextHop) {
		if newAdj, ok = m.AddNextHopsAdj(r.Nhs); ok {
			if newAdj != r.Adj {
				if newAdj == ip.AdjNil {
					f.delFib(m, r)
				}
				oldAdj = r.Adj
				r.Adj = newAdj
				if newAdj != ip.AdjNil {
					f.addFib(m, r)
				}
				if oldAdj != ip.AdjNil {
					m.DelNextHopsAdj(oldAdj)
				}
			} else {
				dbgvnet.Adj.Log("DEBUG oldAdj and newAdj are the same", newAdj)
			}
		} else {
			dbgvnet.Adj.Logf("DEBUG DEBUG failed to get new adj after %v nh %v from %v %v\n",
				vnet.IsDel(isDel), nhIP, f.Name, &p)
			err = fmt.Errorf("failed to get new adj after %v nh %v from %v %v\n",
				vnet.IsDel(isDel), nhIP, f.Name, &p)
		}
	})
	return
}

// In Linux, local route is added to table local when an address is assigned to interface.
// It stays there regardless of whether interface is admin up or down
// Glean route, on the other hand, is added to table main when an interface is admin up, and removed when admin down
// There will be explicit fdb messages to add or delete these routes, so no need to maintain state in vnet
// You can also have multiple local and glean per interface
func (m *Main) AddDelInterfaceAddressRoute(p *net.IPNet, si vnet.Si, rt ip.RouteType, isDel bool) {
	var (
		nhs        ip.NextHopVec
		r          *FibResult
		ok, exists bool
		oldAdj     ip.Adj
		ia         ip.IfAddr
		qq         net.IPNet
	)
	sw := m.Vnet.SwIf(si)
	hw := m.Vnet.SupHwIf(sw)
	f := m.fibBySi(si)
	dbgvnet.Adj.Log(vnet.IsDel(isDel), rt, p, vnet.SiName{V: m.Vnet, Si: si})
	if rt == ip.GLEAN {
		// For glean, need to find the IfAddress based on si and p
		m.Main.ForeachIfAddress(si, func(iadd ip.IfAddr, i *ip.IfAddress) (err error) {
			ipn := i.Prefix
			ip := ipn.IP.Mask(ipn.Mask)
			if p.IP.Equal(ip) {
				qq = ipn
				ia = iadd
				exists = true
			}
			return
		})
	} else {
		// For local, IfAddress is just p
		ia, exists = m.Main.IfAddrForPrefix(p, si)
	}

	dbgvnet.Adj.Log("exists = ", exists)
	// make a NextHopVec with 1 nh with Si=si and empty everthing else for local and glean
	nh := ip.NextHop{Si: si}
	nhs = append(nhs, nh)

	if rt == ip.GLEAN {
		addDelAdj := ip.AdjNil
		if !isDel {
			ai, as := m.NewAdj(1)
			dbgvnet.Adj.Log("set adjacency")
			m.setInterfaceAdjacency(&as[0], si)
			dbgvnet.Adj.Logf("call CallAdjAddHooks(%v)", ai)
			m.CallAdjAddHooks(ai)
			addDelAdj = ai
			dbgvnet.Adj.Log("call Set")
			if oldAdj, r, ok = f.glean.Set(m, p, ai, nhs, GLEAN); ok {
				//if oldAdj, r, ok = f.SetByType(&m.Main, p, ai, nhs, ip.GLEAN_FIB); ok {
				dbgvnet.Adj.Log("call addFib")
				//TBDIP6: call helper
				f.addFib(m, r)
				//m.addFibHelper(f, r)
				dbgvnet.Adj.Logf("set %v glean %v adj %v done\n", f.Name, p, ai)
				if oldAdj != ip.AdjNil {
					dbgvnet.Adj.Logf("DEBUG previous %v glean %v adj %v exist and replace with new adj %v\n",
						f.Name, p, oldAdj, ai)
					if !m.IsAdjFree(oldAdj) {
						m.DelAdj(oldAdj)
					}
				}
			} else {
				dbgvnet.Adj.Logf("DEBUG %v set glean %v adj %v failed\n", f.Name, p, ai)
			}
		}
		if exists {
			ifa := m.GetIfAddr(ia)
			ifa.NeighborProbeAdj = addDelAdj
		} else {
			// set at IfAddress creation
		}
		if isDel {
			dbgvnet.Adj.Log("get Glean")
			if _, r, ok = f.GetGlean(p, si); !ok {
				dbgvnet.Adj.Logf("DEBUG unset %v glean %v not found\n", f.Name, &p)
				return
			}
			dbgvnet.Adj.Log("call delFib")
			//TBDIP6: call helper
			//m.delFibHelper(f, r)
			//if oldAdj, ok = f.UnsetByType(p, r.Nhs, ip.GLEAN_FIB); ok {
			f.delFib(m, r)
			if oldAdj, ok = f.glean.Unset(p, r.Nhs); ok {
				if !m.IsAdjFree(oldAdj) {
					m.DelAdj(oldAdj)
				}
				dbgvnet.Adj.Logf("unset %v glean %v done\n", f.Name, &p)
			}
		}
	}

	if rt == ip.LOCAL {
		if !isDel {
			//TBDIP6: link-local address handling;
			//per interface link-local address should be
			//treated like punt even though every
			//interface has a unique link-local address
			//prefix to be programmed should be fe80/8 per namespace
			if p.IP.IsLinkLocalUnicast() {
				fi := m.Main.FibIndexForSi(si)
				llkey := makeLinklocalKey(p, fi)
				_, found := getCreateLinklocalEntry(p, fi)
				if found {
					//TBDIP6: store ref-count for
					//given netns/fi; ref count helps in
					//deletion case
					dbgvnet.Adj.Logf("maplinklocal found key %v\n", llkey)
					//TBDIP6: revisit
					return
				}
				//TBDIP6: for fib optimization, over-write the link-local addr from the key
				dbgvnet.Adj.Logf("original prefix %v\n", p)
				p.IP = LinklocalUnicast.IP
				dbgvnet.Adj.Logf("new prefix %v\n", p)
			}
			ai, as := m.NewAdj(1)
			as[0].LookupNextIndex = ip.LookupNextLocal
			as[0].Si = si
			if hw != nil {
				as[0].SetMaxPacketSize(hw)
			}
			dbgvnet.Adj.Logf("%v local made new adj %v\n", p, ai)
			m.CallAdjAddHooks(ai)
			dbgvnet.Adj.Logf("%v local added adj %v\n", p, ai)
			if _, r, ok = f.local.Set(m, p, ai, nhs, LOCAL); ok {
				//if _, r, ok = f.SetByType(&m.Main, p, ai, nhs, ip.LOCAL_FIB); ok {
				//TBDIP6: call helper
				//m.addFibHelper(f, r)
				f.addFib(m, r)
				dbgvnet.Adj.Logf("set %v local %v adj %v done\n", f.Name, p, ai)
			} else {
				dbgvnet.Adj.Logf("DEBUG set %v local %v adj %v failed\n", f.Name, p, ai)
			}
		}
		if isDel {
			//TBDIP6: how to delete MapLinklocal
			if _, r, ok = f.GetLocal(p, si); !ok {
				dbgvnet.Adj.Logf("DEBUG unset %v local %v failed\n", f.Name, &p)
				return
			}
			//TBDIP6: call helper
			//m.delFibHelper(f, r)
			//if oldAdj, ok = f.UnsetByType(p, r.Nhs, ip.LOCAL_FIB); ok {
			f.delFib(m, r)
			if oldAdj, ok = f.local.Unset(p, r.Nhs); ok {
				if !m.IsAdjFree(oldAdj) {
					m.DelAdj(oldAdj)
				}
				dbgvnet.Adj.Logf("unset %v local %v done\n", f.Name, &p)
			}
		}
	}
}

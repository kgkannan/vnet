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

type ipFib ip.Fib

var masks = compute_masks()

var lluc = net.IPNet{
	IP:   net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	Mask: net.IPMask{0xff, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
}

// Maps for prefixes for /0 through /32; key in network byte order.
type MapFib [1 + 128]map[string]FibResultVec
type FibResultVec []ip.FibResult

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
	fibs ip.FibVec
	// Hooks to call on set/unset.
	fibAddDelHooks      FibAddDelHookVec
	ifRouteAdjIndexBySi map[vnet.Si]ip.Adj
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
func (m *Main) fibByIndex(i ip.FibIndex, create bool) (f *ip.Fib) {
	m.fibs.Validate(uint(i))
	if create && m.fibs[i] == nil {
		//TBDIP6: fields are not exported; getter method to return new
		//obj
		/*
			m.fibs[i] = &ip.Fib{
				index: i,
				Name: ip.FibName{
					M: &m.Main,
					I: i,
				},
			}
		*/
		m.fibs[i] = ip.GetNewFib(i, &m.Main)
	}
	f = m.fibs[i]
	return
}

func (m *Main) fibById(id ip.FibId, create bool) *ip.Fib {
	var (
		i  ip.FibIndex
		ok bool
	)
	if i, ok = m.FibIndexForId(id); !ok {
		i = ip.FibIndex(m.fibs.Len())
	}
	return m.fibByIndex(i, create)
}

func (m *Main) fibBySi(si vnet.Si) *ip.Fib {
	//i := m.FibIndexForSi(si)
	i := m.ValidateFibIndexForSi(si)
	return m.fibByIndex(i, true)
}

func (m *Main) validateDefaultFibForSi(si vnet.Si) {
	i := m.ValidateFibIndexForSi(si)
	m.fibByIndex(i, true)
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
		r         *ip.FibResult
		ok, found bool
	)

	dbgvnet.Adj.Logf("isDel %v prefix %v adj %v", vnet.IsDel(isDel), p, adj)

	if connected, si := adj.IsConnectedRoute(&m.Main); connected { // arped neighbor
		oldAdj, r, found = f.GetReachable(p, si)
		dbgvnet.Adj.Logf("found %v, adj %v->%v",
			found, oldAdj, adj)
		if isDel && found {
			//TBDIP6: call helper
			//f.delFib(m, r)
			m.delFibHelper(f, r)
			f.AddDelReachable(&m.Main, r, isDel)
			//TBDIP6:
			//oldAdj, ok = f.reachable.UnsetConn(p, si)
			oldAdj, ok = f.UnsetConnByType(p, si, ip.REACHABLE_FIB)
			// neighbor.go takes care of DelAdj so no need to do so here on delete
		}
		if !isDel {
			if found {
				if oldAdj == adj {
					// re-add the fib to hardware as rewrite likely has been updated
					dbgvnet.Adj.Log("update rewrite of adj", adj)
					//TBDIP6: call helper
					//f.addFib(m, r)
					m.addFibHelper(f, r)
					return
				} else {
					// can only have 1 neighbor per prefix/si, so unset any previous
					// should not hit this as ethernet/neighbor.go does a GetReachable first to obtain adj
					dbgvnet.Adj.Logf("DEBUG DEBUG delete previous adj %v before adding new adj %v\n", oldAdj, adj)
					//TBDIP6:
					//oldAdj, ok = f.reachable.UnsetConn(p, si)
					oldAdj, ok = f.UnsetConnByType(p, si, ip.REACHABLE_FIB)
				}
			}
			// create a new reachable entry
			// Set before addFib before addDelReachable in that order
			//TBDIP6:
			//_, r, _ := f.reachable.SetConn(m, p, adj, si)
			_, r, _ := f.SetConnByType(&m.Main, p, adj, si, ip.REACHABLE_FIB)
			//TBDIP6: call helper
			//f.addFib(m, r)
			m.addFibHelper(f, r)
			f.AddDelReachable(&m.Main, r, isDel)
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
		//r, found = f.punt.getInstalled(p)
		r, found = f.GetInstalledByType(p, ip.PUNT_FIB)
		if isDel && found {
			//TBDIP6: call helper
			//f.delFib(m, r)
			m.delFibHelper(f, r)
			//TBDIP6:
			//oldAdj, ok = f.punt.Unset(p, ip.NextHopVec{})
			oldAdj, ok = f.UnsetByType(p, ip.NextHopVec{}, ip.PUNT_FIB)
		}
		if !isDel {
			//TBDIP6:
			//oldAdj, r, ok = f.punt.Set(m, p, adj, ip.NextHopVec{}, ip.PUNT)
			oldAdj, r, ok = f.SetByType(&m.Main, p, adj, ip.NextHopVec{}, ip.PUNT_FIB)
			//TBDIP6: call helper
			//f.addFib(m, r)
			m.addFibHelper(f, r)
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
	k.lladdr = lluc.IP.String()
	k.fi = fi
	dbgvnet.Adj.Logf("llkey = %v\n", k)
	return
}

func updateLinklocalEntry(k LinklocalNetns, update bool) {
	e := LinklocalEntry{}
	if !update {
		//e.llipn.Mask = []byte{0xff, 0xc0}
		//e.llipn.IP[0] = k.IP[0] & llipn.Mask[0]
		//e.llipn.IP[1] = k.IP[1] & llipn.Mask[1]
		e.ref = 1
	} else {
		e = MapLinklocalNetns[k]
		e.ref++
	}
	MapLinklocalNetns[k] = e
	dbgvnet.Adj.Logf("update %v linklocalMap key %v, entry %v\n", k, e)
}

func deleteLinklocalEntry(k LinklocalNetns) {
	e, found := MapLinklocalNetns[k]
	dbgvnet.Adj.Logf("delete %v linklocalMap key %v, entry %v\n", k, e)
	if found {
		e.ref--
		if e.ref == 0 {
			dbgvnet.Adj.Logf("freed %v linklocalMap key %v\n", k)
			delete(MapLinklocalNetns, k)
		}
	}
}

// In Linux, local route is added to table local when an address is assigned to interface.
// It stays there regardless of whether interface is admin up or down
// Glean route, on the other hand, is added to table main when an interface is admin up, and removed when admin down
// There will be explicit fdb messages to add or delete these routes, so no need to maintain state in vnet
// You can also have multiple local and glean per interface
func (m *Main) AddDelInterfaceAddressRoute(p *net.IPNet, si vnet.Si, rt ip.RouteType, isDel bool) {
	var (
		nhs        ip.NextHopVec
		r          *ip.FibResult
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
			//if oldAdj, r, ok = f.glean.Set(m, p, ai, nhs, GLEAN); ok {
			if oldAdj, r, ok = f.SetByType(&m.Main, p, ai, nhs, ip.GLEAN_FIB); ok {
				dbgvnet.Adj.Log("call addFib")
				//TBDIP6: call helper
				//f.addFib(m, r)
				m.addFibHelper(f, r)
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
			//f.delFib(m, r)
			m.delFibHelper(f, r)
			//if oldAdj, ok = f.glean.Unset(p, r.Nhs); ok
			if oldAdj, ok = f.UnsetByType(p, r.Nhs, ip.GLEAN_FIB); ok {
				if !m.IsAdjFree(oldAdj) {
					m.DelAdj(oldAdj)
				}
				dbgvnet.Adj.Logf("unset %v glean %v done\n", f.Name, &p)
			}
		}
	}

	if rt == ip.LOCAL {
		var llkey LinklocalNetns
		if MapLinklocalNetns == nil {
			MapLinklocalNetns = make(map[LinklocalNetns]LinklocalEntry)
		}
		if !isDel {
			//TBDIP6: link-local address handling;
			//per interface link-local address should be
			//treated like punt even though every
			//interface has a unique link-local address
			//prefix to be programmed should be fe80/8 per namespace
			if p.IP.IsLinkLocalUnicast() {
				fi := m.Main.FibIndexForSi(si)
				llkey = makeLinklocalKey(p, fi)
				found := false
				if _, found = MapLinklocalNetns[llkey]; found {
					updateLinklocalEntry(llkey, true)
					//TBDIP6: store ref-count for
					//given netns/fi; ref count helps in
					//deletion case
					dbgvnet.Adj.Logf("maplinklocal found key %v\n", llkey)
					//TBDIP6: revisit
					return
				}
				if !found {
					updateLinklocalEntry(llkey, false)
				}
				//TBDIP6: for fib optimization, over-write the link-local addr from the key
				dbgvnet.Adj.Logf("original prefix %v\n", p)
				p.IP = lluc.IP
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
			//if _, r, ok = f.local.Set(m, p, ai, nhs, LOCAL); ok
			if _, r, ok = f.SetByType(&m.Main, p, ai, nhs, ip.LOCAL_FIB); ok {
				//TBDIP6: call helper
				//f.addFib(m, r)
				m.addFibHelper(f, r)
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
			//f.delFib(m, r)
			m.delFibHelper(f, r)
			//if oldAdj, ok = f.local.Unset(p, r.Nhs); ok
			if oldAdj, ok = f.UnsetByType(p, r.Nhs, ip.LOCAL_FIB); ok {
				if !m.IsAdjFree(oldAdj) {
					m.DelAdj(oldAdj)
				}
				dbgvnet.Adj.Logf("unset %v local %v done\n", f.Name, &p)
			}
		}
	}
}

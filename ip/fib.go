// Copyright 2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ip

import (
	"github.com/platinasystems/elib"
	"github.com/platinasystems/elib/parse"
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/internal/dbgvnet"

	"fmt"
	"net"
	"runtime"
)

// Dense index into fib vector.
type FibIndex uint32

type FibName struct {
	M *Main
	I FibIndex
}

//go:generate gentemplate -d Package=ip -id FibIndex -d VecType=FibIndexVec -d Type=FibIndex github.com/platinasystems/elib/vec.tmpl

// Sparse 32 bit id for route table.
type FibId uint32

type fibMain struct {
	//TODO: common ip4/ip6. add fibs here?
	fibs FibVec
	// Table index indexed by software interface.
	fibIndexBySi FibIndexVec

	nameByIndex elib.StringVec

	// Hash table mapping table id to fib index.
	// ID space is not necessarily dense; index space is dense.
	fibIndexById map[FibId]FibIndex

	// Hash table mapping interface route rewrite adjacency index by sw if index.
	ifRouteAdjBySi map[vnet.Si]FibIndex
}

func (f *fibMain) fibIndexForSi(si vnet.Si, validate bool) FibIndex {
	if validate {
		f.fibIndexBySi.Validate(uint(si))
	}
	return f.fibIndexBySi[si]
}
func (f *fibMain) FibIndexForSi(si vnet.Si) FibIndex {
	return f.fibIndexForSi(si, false)
}
func (f *fibMain) ValidateFibIndexForSi(si vnet.Si) FibIndex {
	return f.fibIndexForSi(si, true)
}

func (m *Main) SetFibIndexForSi(si vnet.Si, fi FibIndex) {
	f := &m.fibMain
	f.fibIndexBySi.Validate(uint(si))
	f.fibIndexBySi[si] = fi
	return
}
func (f *fibMain) FibIndexForId(id FibId) (i FibIndex, ok bool) { i, ok = f.fibIndexById[id]; return }
func (f *fibMain) SetFibIndexForId(id FibId, i FibIndex) {
	if f.fibIndexById == nil {
		f.fibIndexById = make(map[FibId]FibIndex)
	}
	f.fibIndexById[id] = i
}

func (f *fibMain) SetFibNameForIndex(name string, i FibIndex) {
	f.nameByIndex.Validate(uint(i))
	f.nameByIndex[i] = name
}

func (f *fibMain) FibNameForIndex(i FibIndex) string {
	if uint(i) < f.nameByIndex.Len() {
		return f.nameByIndex[i]
	} else {
		return fmt.Sprintf("%d", i)
	}
}

/* helper routine to print the stack trace in a method */
func PrintRuntimeStack(marker string, print bool) {
	if print {
		//increase size for higher stack depth
		trace := make([]byte, 4096)
		count := runtime.Stack(trace, true)
		fmt.Printf("**%s returning %d bytes: %s \n", marker, count, trace)
	}
}

func (n FibName) String() string {
	f := &n.M.fibMain
	if f == nil {
		return fmt.Sprintf("%d", n.I)
	}
	return f.FibNameForIndex(n.I)

}

/* begin: copy-paste code for new ip4/fib.go */
func makeKey(p *net.IPNet) (l uint32, k string) {
	size, _ := p.Mask.Size()
	l = uint32(size)
	k = p.IP.String()
	return
}

type RouteType uint8

const (
	// neighbor
	CONN RouteType = iota
	// has via next hop(s)
	VIA
	// glean
	GLEAN
	// interface addr of vnet recognized interface
	LOCAL
	// punts to Linux
	PUNT
)

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
	default:
		return "unspecified"

	}
}

type FibResult struct {
	m         *Main
	Adj       Adj
	Installed bool
	Prefix    net.IPNet
	Type      RouteType
	Nhs       NextHopVec          // nexthops for Address
	usedBy    mapFibResultNextHop // used to track prefixes that uses Prefix.Address as its nexthop
}
type FibResultVec []FibResult

//type MapFib [1 + 32]map[vnet.Uint32]FibResultVec

//TBDIP6: MapFib common for ipv4 and ipv6
// string key is the string output of the net.IPNet stringer
type MapFib [1 + 128]map[string]FibResultVec

func (r *FibResult) String() (s string) {
	if dbgvnet.Adj == 0 {
		return "noop"
	}
	n := " no nexthops\n"
	if len(r.Nhs) > 0 && r.m != nil {
		n = " nexthops:\n"
		n += r.Nhs.ListNhs(r.m)
	}
	u := "\n"
	if len(r.usedBy) > 0 && r.m != nil {
		u = r.usedBy.ListIPs(r.m)
	}
	s = fmt.Sprintf(" Prefix:%v Type:%v Installed:%v Adj:%v\n%v %v",
		&r.Prefix, r.Type, r.Installed, r.Adj, n, u)
	return
}

func (rs *FibResultVec) ForeachMatchingNhAddress(nha net.IP, fn func(r *FibResult, nh *NextHop)) {
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

// returns first match
func (rs FibResultVec) GetByNhs(nhs NextHopVec) (r FibResult, ri int, ok bool) {
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

func GetNewFib(i FibIndex, m *Main) *Fib {
	newFib := Fib{
		index: i,
		Name: FibName{
			M: m,
			I: i,
		},
	}

	return &newFib
}

func (f *Fib) GetFibIndex() FibIndex {
	if f != nil {
		return (f.index)
	}

	return FibIndex(0)
}

/* TBDIP6: no prefixes specifc info
func (p *Prefix) Mask() vnet.Uint32          { return netMask(uint(p.Len)) }
func (p *Prefix) MaskAsAddress() (a Address) { a.FromUint32(p.Mask()); return }
func (p *Prefix) mapFibKey() vnet.Uint32     { return p.Address.AsUint32() & p.Mask() }
func (p *Prefix) ApplyMask() (q *Prefix) {
	pm := Prefix{}
	pm.Address.FromUint32(p.Address.AsUint32() & p.Mask())
	pm.Len = p.Len
	q = &pm
	return
}
func (a *Address) Mask(l uint) (v Address) {
	v.FromUint32(a.AsUint32() & netMask(l))
	return
}
*/

func (m *MapFib) validateLen(l uint32) {
	if m[l] == nil {
		m[l] = make(map[string]FibResultVec)
	}
}

func (m *MapFib) SetConn(ma *Main, p *net.IPNet, adj Adj, si vnet.Si) (oldAdj Adj, result *FibResult, ok bool) {
	var nhs NextHopVec
	nh := NextHop{Si: si}
	nhs = append(nhs, nh)
	return m.Set(ma, p, adj, nhs, CONN)
}

//TBDIP6:
func (f *Fib) SetByType(ma *Main, p *net.IPNet, newAdj Adj, nhs NextHopVec, t MapFibType) (oldAdj Adj, result *FibResult, ok bool) {
	var mf MapFib
	if t == PUNT_FIB {
		mf = f.punt
	} else if t == GLEAN_FIB {
		mf = f.glean
	}
	oldAdj, result, ok = mf.Set(ma, p, newAdj, nhs, PUNT)
	return
}

func (m *MapFib) UnsetConn(p *net.IPNet, si vnet.Si) (oldAdj Adj, ok bool) {
	var nhs NextHopVec
	nh := NextHop{Si: si}
	nhs = append(nhs, nh)
	return m.Unset(p, nhs)
}

//TBDIP6:
func (f *Fib) UnsetConnByType(p *net.IPNet, si vnet.Si, t MapFibType) (oldAdj Adj, ok bool) {
	if t == REACHABLE_FIB {
		oldAdj, ok = f.reachable.UnsetConn(p, si)
	}
	return
}

//TBDIP6:
func (f *Fib) SetConnByType(ma *Main, p *net.IPNet, adj Adj, si vnet.Si, t MapFibType) (oldAdj Adj, result *FibResult, ok bool) {
	if t == REACHABLE_FIB {
		oldAdj, result, ok = f.reachable.SetConn(ma, p, adj, si)
	}
	return
}

func (m *MapFib) Set(ma *Main, p *net.IPNet, newAdj Adj, nhs NextHopVec, rt RouteType) (oldAdj Adj, result *FibResult, ok bool) {
	l, k := makeKey(p)
	m.validateLen(l)
	var (
		rs FibResultVec
		r  FibResult
		ri int
	)
	oldAdj = AdjNil

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

func (m *MapFib) Unset(p *net.IPNet, nhs NextHopVec) (oldAdj Adj, ok bool) {
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
	oldAdj = AdjNil
	dbgvnet.Adj.Log("DEBUG", p, nhs, "not found")
	return
}

func (m *MapFib) UnsetFirst(p *net.IPNet) (oldAdj Adj, ok bool) {
	l, k := makeKey(p)
	m.validateLen(l)
	var (
		rs FibResultVec
	)
	if rs, ok = m[l][k]; ok {
		if len(rs) > 0 {
			oldAdj = rs[0].Adj
			copy(rs[0:], rs[1:])
			rs = rs[:len(rs)-1]
			if len(rs) == 0 {
				delete(m[l], k)
			} else {
				m[l][k] = rs
			}
			return
		} else {
			ok = false
		}
	}
	oldAdj = AdjNil
	return
}

//TBDIP6:
func (f *Fib) UnsetByType(p *net.IPNet, nhs NextHopVec, t MapFibType) (oldAdj Adj, ok bool) {
	if t == PUNT_FIB {
		oldAdj, ok = f.punt.Unset(p, nhs)
	}
	return
}

func (m *Main) ForeachUnresolved(fn func(fi FibIndex, p net.IPNet)) {
	for _, f := range m.fibs {
		if f == nil {
			continue
		}
		f.unreachable.validateLen(32)
		for _, rs := range f.unreachable[32] {
			for _, r := range rs {
				fn(f.index, r.Prefix)
			}
		}
	}
}

func (m *MapFib) foreach(fn func(p net.IPNet, r FibResult)) {
	for l := 32; l >= 0; l-- {
		//p.Len = uint32(l)
		for _, rs := range m[l] {
			for _, r := range rs {
				//p.Address.FromUint32(k)
				p := r.Prefix
				fn(p, r)
			}
		}
	}
}

func (m *MapFib) reset() {
	for i := range m {
		m[i] = nil
	}
}

// clean remove any reference from REMAINING fib entrys to fi (i.e. 1 fib reference another fib, which is rare)
func (m *MapFib) clean(fi FibIndex) {
	for i := range m {
		for rsi, _ := range m[i] {
			for ri, _ := range m[i][rsi] {
				for dp := range m[i][rsi][ri].usedBy {
					if dp.i == fi {
						delete(m[i][rsi][ri].usedBy, dp)
					}
				}
			}
		}
	}
}

//TBDIP6: hooks should be called by caller
//func (m *MapFib) uninstall_all(f *Fib, ma *Main) {
func (m *MapFib) uninstall_all(f *Fib) {
	for i := range m {
		for rsi, _ := range m[i] {
			for ri, _ := range m[i][rsi] {
				//uninstall from fib table
				//TBDIP6:
				//f.delFib(ma, &m[i][rsi][ri])
				f.DelFib(&m[i][rsi][ri])
			}
		}
	}
}

//TBDIP6: revisit; hooks should be called by caller
// fib local has adjacency in its nh that are not automatically deleted by delFib
//func (m *MapFib) uninstall_local_all(f *Fib, ma *Main) {
func (m *MapFib) uninstall_local_all(f *Fib) {
	for i := range m {
		for rsi, _ := range m[i] {
			for ri, _ := range m[i][rsi] {
				//uninstall from fib table
				r := &m[i][rsi][ri]
				//TBDIP6:
				//oldAdj := r.Adj
				//f.delFib(ma, r)
				f.DelFib(r)
				//TBDIP6: revisit
				/*
					if !ma.IsAdjFree(oldAdj) {
						ma.DelAdj(oldAdj)
					}
				*/
			}
		}
	}
}

type Fib struct {
	index FibIndex
	Name  FibName

	// reachable and unreachable IP address from neighbor messages
	// these have 1 entry per prefix
	reachable, unreachable MapFib

	// routes and their nexthops
	// these can have more than 1 entry per prefix
	routeFib           MapFib //i.e. via nexthop
	local, punt, glean MapFib
}

//TBDIP6:
type MapFibType uint8

const (
	// reachable fib
	REACHABLE_FIB MapFibType = iota
	// unreachable fib
	UNREACHABLE_FIB
	//route fib
	ROUTE_FIB
	// glean fib
	GLEAN_FIB
	// local fib
	LOCAL_FIB
	// punt fib
	PUNT_FIB
)

//go:generate gentemplate -d Package=ip4 -id Fib -d VecType=FibVec -d Type=*Fib github.com/platinasystems/elib/vec.tmpl

// Total number of routes in FIB.
func (f *Fib) Len() (n uint) {
	for i := range f.reachable {
		n += uint(len(f.reachable[i]))
	}
	return
}

type IfAddrAddDelHook func(ia IfAddr, isDel bool)

//go:generate gentemplate -id FibAddDelHook -d Package=ip4 -d DepsType=FibAddDelHookVec -d Type=FibAddDelHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl
//go:generate gentemplate -id IfAddrAddDelHook -d Package=ip4 -d DepsType=IfAddrAddDelHookVec -d Type=IfAddrAddDelHook -d Data=hooks github.com/platinasystems/elib/dep/dep.tmpl

//TBDIP6: marker for refactoring, to export method add to Add
//func (f *Fib) addFib(m *Main, r *FibResult) (installed bool) {
func (f *Fib) AddFib(r *FibResult) (oldr *FibResult, isNew bool) {
	var found bool

	if r == nil {
		panic(fmt.Errorf("addFib got nil FibResult pointer for argument"))
	}
	dbgvnet.Adj.Log(f.Name)
	dbgvnet.AdjPlain.Log(r)
	p := r.Prefix
	// check if there is already an adj installed with same prefix
	oldr, found = f.GetInstalled(&p)

	if !found { // install new
		//TBDIP6: moved code to addFibHelper()
		/*
			m.callFibAddDelHooks(f.index, &p, r.Adj, false)
			installed = true
			r.Installed = installed
		*/
		isNew = true
		dbgvnet.Adj.Log("installed new")
		return
	}

	// something else had previously been installed
	switch r.Type {
	case CONN:
		// always install
	case VIA:
		if oldr.Type == CONN {
			// connected route is preferred, don't install
			// FIXME, as is will replace any previous VIA routes with same prefix
			return
		}
	case GLEAN:
		if oldr.Type == CONN || oldr.Type == VIA {
			// connected and via routes are preferred, don't install
			return
		}
	case LOCAL:
		if oldr.Type == CONN || oldr.Type == VIA || oldr.Type == GLEAN {
			return
		}
	case PUNT:
		// least preferred
		return
	default:
		dbgvnet.Adj.Log("DEBUG unspecifed route type for prefix", &r.Prefix)
		return
	}

	dbgvnet.Adj.Log("call FibAddDelHook", &p, "adj", r.Adj)
	// AddDelHook replaced any previous adj with new on
	//TBDIP6: moved code to addFibHelper()
	/*
		m.callFibAddDelHooks(f.index, &p, r.Adj, false)
		oldr.Installed = false
		installed = true
		r.Installed = installed
	*/
	dbgvnet.Adj.Log("replaced existing")
	return
}

//TBDIP6: marker for refactoring, to export method del to Del
//func (f *Fib) delFib(m *Main, r *FibResult) {
func (f *Fib) DelFib(r *FibResult) (newr *FibResult, found bool) {
	found = false

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
	checkAdjValid := true
	if newr, found = f.reachable.getFirstUninstalled(&p, checkAdjValid); found {
	} else if newr, found = f.routeFib.getFirstUninstalled(&p, checkAdjValid); found {
	} else if newr, found = f.glean.getFirstUninstalled(&p, checkAdjValid); found {
	} else if newr, found = f.local.getFirstUninstalled(&p, checkAdjValid); found {
	} else if newr, found = f.punt.getFirstUninstalled(&p, checkAdjValid); found {
	}

	// uninstall old
	dbgvnet.Adj.Log("call FibAddDelHook", &p, "adj", r.Adj)
	//TBDIP6: call helper
	//m.callFibAddDelHooks(f.index, &p, r.Adj, true)
	//r.Installed = false
	if found {
		dbgvnet.Adj.Logf("call f.addFib to replace with %v\n", newr)
		// install replacement
		//TBDIP6: call helper
		//f.addFib(m, newr)
	}

	return
}

// TBDIP6: no need?
type NextHopper interface {
	AdjacencyFinalizer
	NextHopFibIndex(m *Main) FibIndex
	NextHopWeight() NextHopWeight
}

//TBDIP6: make this generic
type nhUsage struct {
	referenceCount uint32
	nhr            IPNextHop
}

type ipre struct {
	p string // stringer output of net.IPNet
	i FibIndex
}

// idst is the destination or nh address and namespace
// ipre is the prefix that has idst as its nh
//type mapFibResultNextHop map[idst]map[ipre]NextHop
type mapFibResultNextHop map[ipre]nhUsage

func (mp mapFibResultNextHop) ListIPs(m *Main) string {
	if dbgvnet.Adj == 0 {
		return "noop"
	}
	s := "used by: "
	if len(mp) == 0 {
		s += "none"
	}
	for dp, _ := range mp {
		s += fmt.Sprintf(" %v %v;", m.FibNameForIndex(dp.i), dp.p)
	}
	s += "\n"
	return s
}

// This updates the FibResult's usedBy map that prefix p is or is no longer using r as its nexthop
func (r *FibResult) addDelUsedBy(m *Main, pf *Fib, p *net.IPNet, nhr IPNextHop, isDel bool) {
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
func (f *Fib) setReachable(m *Main, p *net.IPNet, pf *Fib, nhr IPNextHop, isDel bool) {
	ip_mask := getNextHopMask(p)
	nhp := net.IPNet{
		IP: nhr.Address,
		//Mask: net.IPv4Mask(255, 255, 255, 255),
		Mask: ip_mask,
	}

	if _, r, found := f.GetReachable(&nhp, nhr.Si); found {
		r.addDelUsedBy(m, pf, p, nhr, isDel)
		dbgvnet.Adj.Logf("%v %v prefix %v via %v, new result\n%v",
			vnet.IsDel(isDel), f.Name, p, nhr.Address, r)
		return
	}
	dbgvnet.Adj.Logf("DEBUG did not find %v in reachable\n", nhr.Address)
}

func getNextHopMask(p *net.IPNet) net.IPMask {
	ip_mask := net.IPMask{}
	if a4 := p.IP.To4(); len(a4) == net.IPv4len {
		ip_mask = net.IPv4Mask(255, 255, 255, 255)
	}
	return ip_mask
}

// create and delete of FibResult entry depends on whether any ViaRoute uses a unresolved as its nexthop, and is done here
func (f *Fib) setUnreachable(m *Main, p *net.IPNet, pf *Fib, nhr IPNextHop, isDel bool) {
	ip_mask := getNextHopMask(p)
	nhp := net.IPNet{
		IP: nhr.Address,
		//Mask: net.IPv4Mask(255, 255, 255, 255),
		Mask: ip_mask,
	}
	var (
		found bool
		r     *FibResult
	)

	if _, r, found = f.GetUnreachable(&nhp, nhr.Si); !found && !isDel {
		_, r, found = f.unreachable.SetConn(m, &nhp, AdjMiss, nhr.Si)
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
func (ur *FibResult) makeReachable(m *Main, f *Fib, adj Adj) {
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

//TBDIP6: export addDel => AddDel
func (f *Fib) AddDelReachable(m *Main, r *FibResult, isDel bool) {
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

func (f *Fib) GetInstalledByType(p *net.IPNet, t MapFibType) (result *FibResult, ok bool) {
	if t == PUNT_FIB {
		result, ok = f.punt.getInstalled(p)
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
			if !r.Installed && !(checkAdjValid && !(r.Adj != AdjNil && r.Adj != AdjMiss)) {
				result = &x[l][k][i]
				return
			}
		}
	}
	ok = false
	return
}

func (x *MapFib) GetBySi(p *net.IPNet, si vnet.Si) (a Adj, result *FibResult, ok bool) {
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
func (x *MapFib) GetByNhs(p *net.IPNet, nhs NextHopVec) (a Adj, result *FibResult, ok bool) {
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

func (f *Fib) GetReachable(p *net.IPNet, si vnet.Si) (a Adj, result *FibResult, ok bool) {
	return f.reachable.GetBySi(p, si)
}
func (f *Fib) GetUnreachable(p *net.IPNet, si vnet.Si) (a Adj, result *FibResult, ok bool) {
	return f.unreachable.GetBySi(p, si)
}
func (f *Fib) GetFib(p *net.IPNet, nhs NextHopVec) (a Adj, result *FibResult, ok bool) {
	return f.routeFib.GetByNhs(p, nhs)
}
func (f *Fib) GetLocal(p *net.IPNet, si vnet.Si) (a Adj, result *FibResult, ok bool) {
	return f.local.GetBySi(p, si)
}
func (f *Fib) GetGlean(p *net.IPNet, si vnet.Si) (a Adj, result *FibResult, ok bool) {
	return f.glean.GetBySi(p, si)
}

// adj is always AdjPunt for punt; just return ok if found
func (f *Fib) GetPunt(p *net.IPNet) (ok bool) {
	var (
		rs FibResultVec
	)
	l, k := makeKey(p)
	f.punt.validateLen(l)
	if rs, ok = f.punt[l][k]; ok {
		if len(rs) > 0 {
			ok = true
		}
	}
	return
}

//TBDIP6: revisit
/*
func (m *Main) setInterfaceAdjacency(a *Adjacency, si vnet.Si) {
	sw := m.Vnet.SwIf(si)
	hw := m.Vnet.SupHwIf(sw)
	var h vnet.HwInterfacer
	if hw != nil {
		h = m.Vnet.HwIfer(hw.Hi())
	}

	next := LookupNextRewrite
	noder := &m.rewriteNode
	packetType := vnet.IP4

	if _, ok := h.(vnet.Arper); h == nil || ok {
		next = LookupNextGlean
		noder = &m.arpNode
		packetType = vnet.ARP
	}

	a.LookupNextIndex = next

	a.Si = si

	if h != nil {
		m.Vnet.SetRewrite(&a.Rewrite, si, noder, packetType, nil // dstAdr meaning broadcast )
	}
}
*/

//TBDIP6: no need of hooks
/*
type FibAddDelHook func(i FibIndex, p *Prefix, r Adj, isDel bool)

func (m *fibMain) RegisterFibAddDelHook(f FibAddDelHook, dep ...*dep.Dep) {
	m.fibAddDelHooks.Add(f, dep...)
}

func (m *fibMain) callFibAddDelHooks(fi FibIndex, p *net.IPNet, r Adj, isDel bool) {
	q := IPNetToV4Prefix(*p)
	for i := range m.fibAddDelHooks.hooks {
		m.fibAddDelHooks.Get(i)(fi, &q, r, isDel)
	}
}
*/

func (m *Main) fibByIndex(i FibIndex, create bool) (f *Fib) {
	m.fibs.Validate(uint(i))
	if create && m.fibs[i] == nil {
		m.fibs[i] = &Fib{
			index: i,
			Name: FibName{
				M: m,
				I: i,
			},
		}
	}
	f = m.fibs[i]
	return
}

func (m *Main) fibById(id FibId, create bool) *Fib {
	var (
		i  FibIndex
		ok bool
	)
	if i, ok = m.FibIndexForId(id); !ok {
		i = FibIndex(m.fibs.Len())
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

func (m *Main) getRoute(p *net.IPNet, si vnet.Si) (ai Adj, as []Adjacency, ok bool) {
	f := m.fibBySi(si)
	if r, found := f.GetInstalled(p); found {
		ok = true
		ai = r.Adj
	}
	if ok {
		as = m.GetAdj(ai)
	}
	return
}

func (m *Main) getReachable(p *net.IPNet, si vnet.Si) (ai Adj, as []Adjacency, ok bool) {
	f := m.fibBySi(si)
	ai, _, ok = f.GetReachable(p, si)
	if ok {
		as = m.GetAdj(ai)
	}
	return
}

func (m *Main) getRouteFibIndex(p *net.IPNet, fi FibIndex) (ai Adj, ok bool) {
	f := m.fibByIndex(fi, false)
	if r, found := f.GetInstalled(p); found {
		ok = true
		ai = r.Adj
	}
	return
}

//TBDIP6: ip specific - should be ip4 or ip6
/*
// Used by neighbor message to add/del route, e.g. from succesfull arp, or install AdjPunt
// Tied to AddDelRoute() and called directly from ethernet/neighbor.go and a few other places
// The adjacency is created/updated elsewhere and the index passed in
func (m *Main) addDelRoute(p *net.IPNet, fi FibIndex, adj Adj, isDel bool) (oldAdj Adj, err error) {
	createFib := !isDel
	f := m.fibByIndex(fi, createFib)
	var (
		r         *FibResult
		ok, found bool
	)

	dbgvnet.Adj.Log(vnet.IsDel(isDel), p, "adj", adj)

	if connected, si := adj.IsConnectedRoute(&m.Main); connected { // arped neighbor
		oldAdj, r, found = f.GetReachable(p, si)
		dbgvnet.Adj.Logf("found %v, adj %v->%v",
			found, oldAdj, adj)
		if isDel && found {
			f.delFib(m, r)
			f.addDelReachable(m, r, isDel)
			oldAdj, ok = f.reachable.UnsetConn(p, si)
			// neighbor.go takes care of DelAdj so no need to do so here on delete
		}
		if !isDel {
			if found {
				if oldAdj == adj {
					// re-add the fib to hardware as rewrite likely has been updated
					dbgvnet.Adj.Log("update rewrite of adj", adj)
					f.addFib(m, r)
					return
				} else {
					// can only have 1 neighbor per prefix/si, so unset any previous
					// should not hit this as ethernet/neighbor.go does a GetReachable first to obtain adj
					dbgvnet.Adj.Logf("DEBUG DEBUG delete previous adj %v before adding new adj %v\n", oldAdj, adj)
					oldAdj, ok = f.reachable.UnsetConn(p, si)
				}
			}
			// create a new reachable entry
			// Set before addFib before addDelReachable in that order
			_, r, _ := f.reachable.SetConn(m, p, adj, si)
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
	if adj == AdjPunt {
		r, found = f.punt.getInstalled(p)
		if isDel && found {
			f.delFib(m, r)
			oldAdj, ok = f.punt.Unset(p, NextHopVec{})
		}
		if !isDel {
			oldAdj, r, ok = f.punt.Set(m, p, adj, NextHopVec{}, PUNT)
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
*/

//TBDIP6: ip4/fib.go defines same data struct declared in ip/adjacency.go
type IPNextHop struct {
	Address net.IP
	Si      vnet.Si
	Weight  NextHopWeight
}

func (n *IPNextHop) NextHopWeight() NextHopWeight     { return n.Weight }
func (n *IPNextHop) NextHopFibIndex(m *Main) FibIndex { return m.FibIndexForSi(n.Si) }
func (n *IPNextHop) FinalizeAdjacency(a *Adjacency)   {}

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

//TBDIP6: revisit
/*
type prefixError struct {
	s string
	p Prefix
}

func (e *prefixError) Error() string { return e.s + ": " + e.p.String() }
*/

func (m *Main) updateAdjAndUsedBy(f *Fib, p *net.IPNet, nhs *NextHopVec, isDel bool) {
	dbgvnet.Adj.Log(f.Name, p, vnet.IsDel(isDel))
	ip_mask := getNextHopMask(p)
	for nhi, nh := range *nhs {
		var (
			adj   Adj
			found bool
		)
		nhp := net.IPNet{
			IP: nh.Address,
			//Mask: net.IPv4Mask(255, 255, 255, 255),
			Mask: ip_mask,
		}
		nhr := IPNextHop{
			Address: nh.Address,
			Si:      nh.Si,
			Weight:  nh.Weight,
		}
		nhf := m.fibByIndex(nh.NextHopFibIndex(m), true) // fib/namesapce that nh.Si belongs to

		adj, _, found = nhf.GetReachable(&nhp, nh.Si) // adj = 0(AdjMiss) if not found

		// if add, need to update the adj as it will not have been filled in yet
		if !isDel {
			(*nhs)[nhi].Adj = adj

			if adj == AdjMiss {
				// adding a punt to arp
				//(*nhs)[nhi].Adj = AdjPunt
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
func (m *Main) AddDelRouteNextHops(fibIndex FibIndex, p *net.IPNet, nhs NextHopVec, isDel bool, isReplace bool) (err error) {
	f := m.fibByIndex(fibIndex, true)
	dbgvnet.Adj.Logf("%v %v %v isReplace %v, nhs: \n%v\n",
		vnet.IsDel(isDel), f.Name, p, isReplace, nhs.ListNhs(m))
	var (
		r      *FibResult
		ok     bool
		oldAdj Adj
	)
	if isDel {
		if oldAdj, r, ok = f.GetFib(p, nhs); ok {
			//TBDIP6:
			//f.delFib(m, r) // remove from fib
			_, _ = f.DelFib(r) // remove from fib
		} else {
			dbgvnet.Adj.Log("DEBUG delete, cannot find", f.Name, p)
			err = fmt.Errorf("AddDelRouteNextHops delete, cannot find %v %v\n", f.Name, &p)
		}
	}
	if isReplace {
		if r, ok = f.routeFib.getInstalled(p); ok {
			//TBDIP6:
			//f.delFib(m, r)
			_, _ = f.DelFib(r)
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
			if len(f.routeFib[l][k]) == 1 && r.Adj != AdjNil {
				// first via route for prefix p; try installing it
				//TBDIP6:
				//f.addFib(m, r) // add
				_, _ = f.AddFib(r) // add
			}
		} else {
			dbgvnet.Adj.Log("DEBUG failed to get adj for", f.Name, p)
		}
	}
	return
}

// modified for legacy netlink and ip/cli use, where nexthop were added 1 at a time instead of a vector at at time
func (m *Main) AddDelRouteNextHop(p *net.IPNet, nh *NextHop, isDel bool, isReplace bool) (err error) {
	var nhs NextHopVec
	new_nh := NextHop{
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
func (f *Fib) addDelRouteNextHop(m *Main, p *net.IPNet, nhIP net.IP, nhr NextHopper, nhAdj Adj, isDel bool) (err error) {
	var (
		oldAdj, newAdj Adj
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
	newAdj = AdjNil

	// update rs with nhAdj if reachable (add) or a new arp adj if unreachale (del); detele oldAj
	rs.ForeachMatchingNhAddress(nhIP, func(r *FibResult, nh *NextHop) {
		if isDel {
			//ai, as := m.NewAdj(1)
			//m.setArpAdjacency(&as[0], nh.Si)
			//nh.Adj = ai
			nh.Adj = AdjMiss
		} else {
			nh.Adj = nhAdj
		}
	})

	// Do this as separate ForEach because r.Nhs will not have been updated until the ForeachMatchingNhAddress completed
	// update with newAdj and addFib
	rs.ForeachMatchingNhAddress(nhIP, func(r *FibResult, nh *NextHop) {
		if newAdj, ok = m.AddNextHopsAdj(r.Nhs); ok {
			if newAdj != r.Adj {
				if newAdj == AdjNil {
					//TBDIP6:
					//f.delFib(m, r)
					f.DelFib(r)
				}
				oldAdj = r.Adj
				r.Adj = newAdj
				if newAdj != AdjNil {
					//TBDIP6:
					//f.addFib(m, r)
					_, _ = f.AddFib(r)
				}
				if oldAdj != AdjNil {
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

//TBDIP6: revisit

// In Linux, local route is added to table local when an address is assigned to interface.
// It stays there regardless of whether interface is admin up or down
// Glean route, on the other hand, is added to table main when an interface is admin up, and removed when admin down
// There will be explicit fdb messages to add or delete these routes, so no need to maintain state in vnet
// You can also have multiple local and glean per interface
func (m *Main) AddDelInterfaceAddressRoute(p *net.IPNet, si vnet.Si, rt RouteType, isDel bool) {
	var (
		nhs        NextHopVec
		r          *FibResult
		ok, exists bool
		oldAdj     Adj
		ia         IfAddr
		qq         net.IPNet
	)
	sw := m.v.SwIf(si)
	hw := m.v.SupHwIf(sw)
	f := m.fibBySi(si)
	dbgvnet.Adj.Log(vnet.IsDel(isDel), rt, p, vnet.SiName{V: m.v, Si: si})
	if rt == GLEAN {
		//TBDIP6: Foreachifaddress needs just ip.Fib.Main
		// For glean, need to find the IfAddress based on si and p
		m.ForeachIfAddress(si, func(iadd IfAddr, i *IfAddress) (err error) {
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
		//TBDIP6: Foreachifaddress needs just ip.Fib.Main
		//ia, exists = m.Main.IfAddrForPrefix(p, si)
		ia, exists = m.IfAddrForPrefix(p, si)
	}

	dbgvnet.Adj.Log("exists = ", exists)
	// make a NextHopVec with 1 nh with Si=si and empty everthing else for local and glean
	nh := NextHop{Si: si}
	nhs = append(nhs, nh)

	if rt == GLEAN {
		addDelAdj := AdjNil
		if !isDel {
			var ai Adj
			dbgvnet.Adj.Log("set adjacency")
			//ai, as := m.NewAdj(1)
			ai, _ = m.NewAdj(1)
			//TBDIP6: revisit make this generic; move this to vnet/ip/adj or
			//interface
			//m.setInterfaceAdjacency(&as[0], si)
			dbgvnet.Adj.Logf("call CallAdjAddHooks(%v)", ai)
			m.CallAdjAddHooks(ai)
			addDelAdj = ai
			dbgvnet.Adj.Log("call Set")
			if oldAdj, r, ok = f.glean.Set(m, p, ai, nhs, GLEAN); ok {
				dbgvnet.Adj.Log("call addFib")
				//TBDIP6:
				//f.addFib(m, r)
				_, _ = f.AddFib(r)
				dbgvnet.Adj.Logf("set %v glean %v adj %v done\n", f.Name, p, ai)
				if oldAdj != AdjNil {
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
			//TBDIP6:
			//f.delFib(m, r)
			_, _ = f.DelFib(r)
			if oldAdj, ok = f.glean.Unset(p, r.Nhs); ok {
				if !m.IsAdjFree(oldAdj) {
					m.DelAdj(oldAdj)
				}
				dbgvnet.Adj.Logf("unset %v glean %v done\n", f.Name, &p)
			}
		}
	}

	if rt == LOCAL {
		if !isDel {
			ai, as := m.NewAdj(1)
			as[0].LookupNextIndex = LookupNextLocal
			as[0].Si = si
			if hw != nil {
				as[0].SetMaxPacketSize(hw)
			}
			dbgvnet.Adj.Logf("%v local made new adj %v\n", p, ai)
			m.CallAdjAddHooks(ai)
			dbgvnet.Adj.Logf("%v local added adj %v\n", p, ai)
			if _, r, ok = f.local.Set(m, p, ai, nhs, LOCAL); ok {
				//TBDIP6:
				//f.addFib(m, r)
				_, _ = f.AddFib(r)
				dbgvnet.Adj.Logf("set %v local %v adj %v done\n", f.Name, p, ai)
			} else {
				dbgvnet.Adj.Logf("DEBUG set %v local %v adj %v failed\n", f.Name, p, ai)
			}
		}
		if isDel {
			if _, r, ok = f.GetLocal(p, si); !ok {
				dbgvnet.Adj.Logf("DEBUG unset %v local %v failed\n", f.Name, &p)
				return
			}
			//TBDIP6:
			//f.delFib(m, r)
			_, _ = f.DelFib(r)
			if oldAdj, ok = f.local.Unset(p, r.Nhs); ok {
				if !m.IsAdjFree(oldAdj) {
					m.DelAdj(oldAdj)
				}
				dbgvnet.Adj.Logf("unset %v local %v done\n", f.Name, &p)
			}
		}
	}
}

//TBDIP6: revisit; make vnet/ip/interface.go:AddDelInterfaceAddress generic for
//ip4 and ip6
/*
func (m *Main) AddDelInterfaceAddress(si vnet.Si, addr *net.IPNet, isDel bool) (err error) {
	if !isDel {
		// FIXME, should we disallow or let it add anyway?
		err = m.ForeachIfAddress(si, func(ia IfAddr, ifa *IfAddress) (err error) {
			p := &ifa.Prefix
			if (p.String() != addr.String()) && (addr.Contains(p.IP) || p.Contains(addr.IP)) {
				err = fmt.Errorf("%s: add %s conflicts with existing address %s", vnet.SiName{V: m.v, Si: si}, addr, &p)
				dbgvnet.Adj.Logf("DEBUG %s: add %s conflicts with existing address %s", vnet.SiName{V: m.v, Si: si}, addr, &p)
			}
			return
		})
		if err != nil {
			return
		}
	}

	var (
		ia     IfAddr
		exists bool
	)

	// Fib remove messages should have came from Linux and fdb before InterfaceAddress remove
	// Check and flag just in case, as Local/Glean adjacencies contains index to IfAddress so
	// could be a problem is IfAddress is freed, but index is still used
	if isDel && dbgvnet.Adj > 0 {
		//TBDIP6: IfAddrForPrefix needs just ip.Fib.Main
		ia, exists = m.IfAddrForPrefix(addr, si)
		f := m.fibBySi(si)
		if adj, _, found := f.GetLocal(addr, si); found {
			dbgvnet.Adj.Logf("DEBUG deleting IfAddr %v, but it is still used by local route %v adj %v\n",
				addr, addr, adj)
		}
		q := &net.IPNet{
			IP:   addr.IP.Mask(addr.Mask),
			Mask: addr.Mask,
		}
		if adj, _, found := f.GetGlean(q, si); found {
			dbgvnet.Adj.Logf("DEBUG deleting IfAddr %v, but it is still used by glean route %v adj %v\n",
				addr, q.String(), adj)
		}
	}

	// Add/Delete interface address.  Return error if deleting non-existent address.
	//TBDIP6: IfAddrForPrefix needs just ip.Fib.Main
	if ia, exists, err = m.AddDelInterfaceAddress(si, addr, isDel); err != nil {
		return
	}

	if !isDel {
		f := m.fibBySi(si)
		q := &net.IPNet{
			IP:   addr.IP.Mask(addr.Mask),
			Mask: addr.Mask,
		}
		if adj, _, found := f.GetGlean(q, si); found {
			ifa := m.GetIfAddr(ia)
			ifa.NeighborProbeAdj = adj
		} else {
			// will be set when glean is created
		}
	}

	// Do callbacks when new address is created or old one is deleted.
	if isDel || !exists {
		for i := range m.ifAddrAddDelHooks.hooks {
			//TBDIP6:
			//m.ifAddrAddDelHooks.Get(i)(ia, isDel)
		}
	}

	return
}
*/

//TBDIP6: leverage swifAddDel in ip/interface.go

// function registered in ip4/pacckage.go as SwIfAddDelHook
// Normally local and glean entries are cleaned up from explicit Linux fib messages.
// The exception is if namespace was deleted before the interface/fib messages where set to vnet
/*
func (m *Main) swIfAddDel(v *vnet.Vnet, si vnet.Si, isUp bool) (err error) {
	if isUp {
		// nothing to do for add;
		return
	}
	f := m.fibBySi(si)
	dbgvnet.Adj.Logf("clean up %v %v %v up=%v",
		f.Name, si, vnet.SiName{V: v, Si: si}, isUp)
	mp := &f.glean
	mp_string := "glean"
	for _, local := range [2]bool{false, true} {
		if local {
			mp = &f.local
			mp_string = "local"
		}
		for i := range mp {
			for rsi, _ := range mp[i] {
				for ri, r := range mp[i][rsi] {
					for _, nh := range mp[i][rsi][ri].Nhs {
						if nh.Si == si {
							dbgvnet.Adj.Logf("clean up %v %v %v\n",
								f.Name, mp_string, vnet.SiName{V: v, Si: si}, &r.Prefix)
							f.delFib(m, &mp[i][rsi][ri])
						}
					}
				}
			}
		}
	}
	return
}
*/

//TBDIP6: made generic in ip/interface.go
// function registered in ip4/package.go as a SwIfAdminUpDownHook
func (m *Main) swIfAdminUpDown(v *vnet.Vnet, si vnet.Si, isUp bool) (err error) {
	m.validateDefaultFibForSi(si)
	f := m.fibBySi(si)
	m.ForeachIfAddress(si, func(ia IfAddr, ifa *IfAddress) (err error) {
		// Do not need to do anything for glean
		// Linux and fdb will send explicit message to add/del glean routes on admin up/down

		// Do need to install/uninstall local adjacency; but not add/del the local route itself
		p := ifa.Prefix
		if _, r, ok := f.GetLocal(&p, si); ok {
			if isUp {
				//TBDIP6:
				//f.addFib(m, r)
				_, _ = f.AddFib(r)
			} else {
				//TBDIP6:
				//f.delFib(m, r)
				_, _ = f.DelFib(r)
			}
		}
		return
	})
	return
}

func (f *Fib) Reset() {
	dbgvnet.Adj.Logf("clear out all fibs in %v\n", f.index)
	f.reachable.reset()
	f.unreachable.reset()
	f.routeFib.reset()
	f.local.reset()
	f.glean.reset()
	f.punt.reset()
}

func (m *Main) FibReset(fi FibIndex) {
	f := m.fibByIndex(fi, true)
	for i := range m.fibs {
		if i != int(fi) && m.fibs[i] != nil {
			dbgvnet.Adj.Logf("clean up %v reachable references in other fibs\n", f.Name)
			m.fibs[i].reachable.clean(fi)
			dbgvnet.Adj.Logf("clean up %v unreachable references in other fibs\n", f.Name)
			m.fibs[i].unreachable.clean(fi)
		}
	}

	dbgvnet.Adj.Logf("uninstall_all %v reachable\n", f.Name)
	//TBDIP6:
	//f.reachable.uninstall_all(f, m)
	f.reachable.uninstall_all(f)
	dbgvnet.Adj.Logf("uninstall_all %v unreachable\n", f.Name)
	//TBDIP6:
	//f.unreachable.uninstall_all(f, m)
	f.unreachable.uninstall_all(f)
	dbgvnet.Adj.Logf("uninstall_all %v via routes\n", f.Name)
	//TBDIP6:
	//f.routeFib.uninstall_all(f, m)
	f.routeFib.uninstall_all(f)
	dbgvnet.Adj.Logf("uninstall_all %v local\n", f.Name)
	//TBDIP6:
	//f.local.uninstall_local_all(f, m)
	f.local.uninstall_local_all(f)
	dbgvnet.Adj.Logf("uninstall_all %v glean\n", f.Name)
	//TBDIP6:
	//f.glean.uninstall_all(f, m)
	f.glean.uninstall_all(f)
	dbgvnet.Adj.Logf("uninstall_all %v punt\n", f.Name)
	//TBDIP6:
	//f.punt.uninstall_all(f, m)
	f.punt.uninstall_all(f)

	f.Reset()
}

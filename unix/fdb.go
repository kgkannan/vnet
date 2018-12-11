// Copyright 2018 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// File to catch message updates from linux kernel (via platina-mk1 driver) that
// signal different networking events (replacement for netlink.go)
//  - prefix/nexthop add/delete/replace
//  - ifaddr add/delete
//  - ifinfo (admin up/down)
//  - neighbor add/delete/replace
//
package unix

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"github.com/platinasystems/elib/cli"
	"github.com/platinasystems/elib/loop"
	"github.com/platinasystems/vnet"
	"github.com/platinasystems/vnet/ethernet"
	"github.com/platinasystems/vnet/internal/dbgvnet"
	"github.com/platinasystems/vnet/ip"
	"github.com/platinasystems/vnet/ip4"
	"github.com/platinasystems/vnet/ip6"
	"github.com/platinasystems/vnet/unix/internal/dbgfdb"
	"github.com/platinasystems/xeth"
)

var (
	// Function flags
	FdbOn       bool = true
	AllowBridge bool = true
)

const (
	UNSUPPORTED_VLAN_CTAG_RANGE_MIN = 3000 + iota
	UNSUPPORTED_VLAN_CTAG_RANGE_MAX = 3999
)

const MAXMSGSPEREVENT = 1000

type fdbEvent struct {
	vnet.Event
	fm      *FdbMain
	evType  vnet.ActionType
	NumMsgs int
	Msgs    [MAXMSGSPEREVENT][]byte

	sync.Mutex
	currMsg currMsgType
}

type currMsgType struct {
	id   int
	kind xeth.Kind
}

type FdbMain struct {
	loop.Node
	m         *Main
	eventPool sync.Pool
}

func (fm *FdbMain) Init(m *Main) {
	fm.m = m
	fm.eventPool.New = fm.newEvent
	l := fm.m.v.GetLoop()
	fm.cliInit()
	l.RegisterNode(fm, "fdb-listener")
}

// This needs to be used to initialize the eventpool
func (m *FdbMain) newEvent() interface{} {
	return &fdbEvent{fm: m}
}

func (m *FdbMain) GetEvent(evType vnet.ActionType) *fdbEvent {
	v := m.eventPool.Get().(*fdbEvent)
	*v = fdbEvent{
		fm:      m,
		evType:  evType,
		NumMsgs: 0,
		Msgs:    [MAXMSGSPEREVENT][]byte{},
		currMsg: currMsgType{},
	}
	return v
}

func (e *fdbEvent) Signal() {
	if len(e.Msgs) > 0 {
		e.fm.m.v.SignalEvent(e)
	}
}

func (e *fdbEvent) put() {
	e.NumMsgs = 0
	// Zero out array?
	e.fm.eventPool.Put(e)
}

func (e *fdbEvent) String() (s string) {
	e.Lock()
	defer e.Unlock()
	s = "fdb msgs"
	l := e.NumMsgs
	if l > 0 {
		s = fmt.Sprintf("fdb msg %v out of %v: %v",
			e.currMsg.id, l, e.currMsg.kind)
	}
	return
}

func (e *fdbEvent) EnqueueMsg(msg []byte) bool {
	if e.NumMsgs+1 > MAXMSGSPEREVENT {
		return false
	}
	e.Msgs[e.NumMsgs] = msg
	e.NumMsgs++
	return true
}

func initVnetFromXeth(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain

	// Initiate walk of PortEntry map to send vnetd
	// interface info and namespaces
	ProcessInterfaceInfo(nil, vnet.ReadyVnetd, v)

	// Initiate walk of PortEntry map to send IFAs
	ProcessInterfaceAddr(nil, vnet.ReadyVnetd, v)

	/* TBDIP6 */
	// Initiate walk of PortEntry map to send IFAs
	//ProcessInterfaceIp6Addr(nil, vnet.ReadyVnetd, v)

	// Initiate walk of PortEntry map to send vnetd ethtool data
	InitInterfaceEthtool(v)

	// Send events for initial dump of fib entries
	fe := fdbm.GetEvent(vnet.Dynamic)
	xeth.DumpFib()
	for msg := range xeth.RxCh {
		if kind := xeth.KindOf(msg); kind == xeth.XETH_MSG_KIND_BREAK {
			xeth.Pool.Put(msg)
			break
		}
		if ok := fe.EnqueueMsg(msg); !ok {
			// filled event with messages so send it and continue
			fe.Signal()
			fe = fdbm.GetEvent(vnet.Dynamic)
			if ok = fe.EnqueueMsg(msg); !ok {
				panic("can't enqueue initial fdb dump")
			}
		}
	}
	fe.Signal()

	// Drain XETH channel into vnet events.
	go gofdb(v)
}

func gofdb(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain
	fe := fdbm.GetEvent(vnet.Dynamic)
	for msg := range xeth.RxCh {
		if ok := fe.EnqueueMsg(msg); !ok {
			fe.Signal()
			fe = fdbm.GetEvent(vnet.Dynamic)
			if ok = fe.EnqueueMsg(msg); !ok {
				panic("Can't enqueue fdb")
			}
		}
		if len(xeth.RxCh) == 0 {
			fe.Signal()
			fe = fdbm.GetEvent(vnet.Dynamic)
		}
	}
}

func (e *fdbEvent) EventAction() {
	var err error
	m := e.fm
	vn := m.m.v

	for i := 0; i < e.NumMsgs; i++ {
		msg := e.Msgs[i]
		kind := xeth.KindOf(msg)
		dbgfdb.XethMsg.Log("kind:", kind)
		ptr := unsafe.Pointer(&msg[0])
		e.Lock()
		e.currMsg = currMsgType{id: i, kind: kind}
		e.Unlock()
		switch xeth.KindOf(msg) {
		/*
		 * TBDIP6:
		 * case xeth.XETH_MSG_KIND_NEIGH_UPDATE:
		 *	err = ProcessIp6Neighbor((*xeth.MsgNeighUpdate)(ptr), e.evType, vn)
		 */
		case xeth.XETH_MSG_KIND_NEIGH_UPDATE:
			err = ProcessIpNeighbor((*xeth.MsgNeighUpdate)(ptr), vn)
		/*
		 * TBDIP6:
		 * case xeth.XETH_MSG_KIND_FIBENTRY:
		 *	err = ProcessIp6FibEntry((*xeth.MsgFibEntry)(ptr), e.evType, vn)
		 */
		case xeth.XETH_MSG_KIND_FIBENTRY:
			err = ProcessFibEntry((*xeth.MsgFibentry)(ptr), vn)
		/*
		 * TBDIP6:
		 * case xeth.XETH_MSG_KIND_IFA:
		 *	err = ProcessInterfaceIp6Addr((*xeth.MsgIfa)(ptr), e.evType, vn)
		 */
		case xeth.XETH_MSG_KIND_IFA:
			err = ProcessInterfaceAddr((*xeth.MsgIfa)(ptr), e.evType, vn)
		case xeth.XETH_MSG_KIND_IFINFO:
			err = ProcessInterfaceInfo((*xeth.MsgIfinfo)(ptr), e.evType, vn)
		case xeth.XETH_MSG_KIND_CHANGE_UPPER:
			if AllowBridge {
				err = ethernet.ProcessChangeUpper((*xeth.MsgChangeUpper)(ptr), e.evType, vn)
			}
		case xeth.XETH_MSG_KIND_ETHTOOL_FLAGS:
			msg := (*xeth.MsgEthtoolFlags)(ptr)
			xethif := xeth.Interface.Indexed(msg.Ifindex)
			ifname := xethif.Ifinfo.Name
			vnet.Ports.SetPort(ifname).Flags =
				xeth.EthtoolPrivFlags(msg.Flags)
			fec91 := vnet.PortIsFec91(ifname)
			fec74 := vnet.PortIsFec74(ifname)
			dbgfdb.IfETFlag.Log(ifname, "fec91", fec91, "fec74", fec74)
			var fec ethernet.ErrorCorrectionType
			// if both fec91 and fec74 are on, set fec to fec91
			if fec91 {
				fec = ethernet.ErrorCorrectionCL91
			} else if fec74 {
				fec = ethernet.ErrorCorrectionCL74
			} else {
				fec = ethernet.ErrorCorrectionNone
			}
			media := "fiber"
			if vnet.PortIsCopper(ifname) {
				media = "copper"
			}
			dbgfdb.IfETFlag.Log(ifname, media)
			hi, found := vn.HwIfByName(ifname)
			if found {
				dbgfdb.IfETFlag.Log(ifname, "setting",
					"media", media, "fec", fec)
				hi.SetMedia(vn, media)
				err = ethernet.SetInterfaceErrorCorrection(vn, hi, fec)
				dbgfdb.IfETFlag.Log(err, "on", ifname)
			}
		case xeth.XETH_MSG_KIND_ETHTOOL_SETTINGS:
			msg := (*xeth.MsgEthtoolSettings)(ptr)
			xethif := xeth.Interface.Indexed(msg.Ifindex)
			ifname := xethif.Ifinfo.Name
			vnet.Ports.SetPort(ifname).Speed =
				xeth.Mbps(msg.Speed)
			hi, found := vn.HwIfByName(ifname)
			if found {
				var bw float64
				if msg.Autoneg == 0 {
					bw = float64(msg.Speed)
				}
				speedOk := false
				dbgfdb.IfETSetting.Log(ifname, "setting speed", bw)
				switch bw {
				case 0, 1000, 10000, 20000, 25000, 40000, 50000, 100000:
					speedOk = true
				}
				if !speedOk {
					err = fmt.Errorf("unexpected speed: %v",
						bw)
					dbgfdb.IfETSetting.Log(err, "on", ifname)
				} else {
					bw *= 1e6
					err = hi.SetSpeed(vn, vnet.Bandwidth(bw))
					dbgfdb.IfETSetting.Log(err, "on", ifname)
				}
			}

		}
		dbgfdb.XethMsg.Log(err, "with kind", kind)
		xeth.Pool.Put(msg)
	}
	e.put()
}

func ipnetToIP4Prefix(ipnet *net.IPNet) (p ip4.Prefix) {
	for i := range ipnet.IP {
		p.Address[i] = ipnet.IP[i]
	}
	maskOnes, _ := ipnet.Mask.Size()
	p.Len = uint32(maskOnes)
	return
}

func (ns *net_namespace) parseIP4NextHops(msg *xeth.MsgFibentry) (nhs ip.NextHopVec) {
	if ns == nil {
		dbgfdb.Fib.Log("ns is nil")
	} else {
		dbgfdb.Fib.Log("ns is", ns.name)
	}
	xethNhs := msg.NextHops()
	dbgfdb.Fib.Log(len(xethNhs), "nexthops")
	nh := ip.NextHop{}
	for _, xnh := range xethNhs {
		intf := ns.interface_by_index[uint32(xnh.Ifindex)]
		if intf == nil {
			dbgfdb.Fib.Log("no ns-intf for ifindex",
				xnh.Ifindex)
			continue
		}
		nh.Si = intf.si
		nh.Weight = ip.NextHopWeight(xnh.Weight)
		if nh.Weight == 0 {
			nh.Weight = 1
		}
		nh.Address = xnh.IP()
		dbgvnet.Adj.Logf("nh.Address %v xnh.IP() %v xnh %v",
			nh.Address, xnh.IP(), xnh)
		nhs = append(nhs, nh)
	}
	return
}

func ipnetToIPPrefixHelper(ipnet *net.IPNet) (p ip.Prefix) {
	for i := range ipnet.IP {
		p.Address[i] = ipnet.IP[i]
	}
	maskOnes, _ := ipnet.Mask.Size()
	p.Len = uint32(maskOnes)
	return
}

func ipnetToIP6Prefix(ipnet *net.IPNet) (p ip6.Prefix) {
	for i := range ipnet.IP {
		p.Address[i] = ipnet.IP[i]
	}
	maskOnes, _ := ipnet.Mask.Size()
	p.Len = uint32(maskOnes)
	return
}

func (ns *net_namespace) parseIP4NextHops_old(msg *xeth.MsgFibentry) (nhs []ip4_next_hop) {

	if ns.ip4_next_hops != nil {
		ns.ip4_next_hops = ns.ip4_next_hops[:0]
	}
	nhs = ns.ip4_next_hops

	if ns == nil {
		dbgfdb.Fib.Log("ns is nil")
	} else {
		dbgfdb.Fib.Log("ns is", ns.name)
	}
	xethNhs := msg.NextHops()
	dbgfdb.Fib.Log(len(xethNhs), "nexthops")
	for i, _ := range xethNhs {
		dbgfdb.Fib.Logf("nexthops[%d]: %#v", i, xethNhs[i])
	}

	// If only 1 nh then assume this is single OIF nexthop
	// otherwise it's multipath
	nh := ip4_next_hop{}
	nh.Weight = 1
	if len(xethNhs) == 1 {
		nh.intf = ns.interface_by_index[uint32(xethNhs[0].Ifindex)]
		if nh.intf == nil {
			dbgfdb.Fib.Log("no ns-intf for ifindex",
				xethNhs[0].Ifindex)
			return
		}
		nh.Si = nh.intf.si
		copy(nh.Address[:], xethNhs[0].IP())
		nhs = append(nhs, nh)
	} else {
		for _, xnh := range xethNhs {
			intf := ns.interface_by_index[uint32(xnh.Ifindex)]
			if intf == nil {
				dbgfdb.Fib.Log("no ns-intf for ifindex",
					xnh.Ifindex)
				continue
			}
			nh.Si = intf.si
			nh.Weight = ip.NextHopWeight(xnh.Weight)
			if nh.Weight == 0 {
				nh.Weight = 1
			}
			copy(nh.Address[:], xnh.IP())
			nhs = append(nhs, nh)
		}
	}
	ns.ip4_next_hops = nhs // save for next call
	return
}

//TBDIP6: PRG
//v1 without method;
//options: avoid duplicate/parallel path for ipv6 and ipv4
func ProcessSingleIpNexthop(ns *net_namespace, xeth_nh xeth.NextHop, ip_nh ip_next_hop) (err error) {
	intf := ns.interface_by_index[uint32(xeth_nh.Ifindex)]
	if intf == nil {
		dbgfdb.Fib.Log("no ns-intf for ifindex",
			xeth_nh.Ifindex)
		return
	}

	if ip_nh.is_ip4 {
		nhs := ip_nh.ip4_nhs
		//call a methods that returns an interface?
		nh := ip4_next_hop{}
		nh.intf = intf
		nh.Weight = ip.NextHopWeight(1)
		if xeth_nh.Weight != 0 {
			nh.Weight = ip.NextHopWeight(xeth_nh.Weight)
		}
		nh.Si = intf.si
		copy(nh.Address[:], xeth_nh.IP())
		nhs = append(nhs, nh)
	} else {
		nhs := ip_nh.ip6_nhs
		nh := ip6_next_hop{}
		nh.intf = intf
		nh.Weight = ip.NextHopWeight(1)
		if xeth_nh.Weight != 0 {
			nh.Weight = ip.NextHopWeight(xeth_nh.Weight)
		}
		nh.Si = intf.si
		copy(nh.Address[:], xeth_nh.IP())
		nhs = append(nhs, nh)
	}

	return nil
}

//TBDIP6: PRG
func ProcessMultipleIpNexthops(ns *net_namespace, xethNhs []xeth.NextHop, ip_nh ip_next_hop) {
	for _, xnh := range xethNhs {
		ret := ProcessSingleIpNexthop(ns, xnh, ip_nh) //.Ifindex, ip.NextHopWeight(xnh.Weight), xnh.IP())
		if ret != nil {
			//log message
		}
		/*
			intf := ns.interface_by_index[uint32(xnh.Ifindex)]
			if intf == nil {
				dbgfdb.Fib.Log("no ns-intf for ifindex",
					xnh.Ifindex)
				continue
			}
			nh.Si = intf.si
			nh.Weight = ip.NextHopWeight(xnh.Weight)
			if nh.Weight == 0 {
				nh.Weight = 1
			}
			copy(nh.Address[:], xnh.IP())
			nhs = append(nhs, nh)
		*/
	}

}

//TBDIP6: PRG
//common helper method to parse ip4 or ip6 nhs; set ip_next_hop.is_ipv4 for ipv4
func (ns *net_namespace) parseIPNextHopsHelper(msg *xeth.MsgFibentry, family uint8) (ip_nh ip_next_hop) {
	if family != syscall.AF_INET {
		if ns.ip4_next_hops != nil {
			ns.ip4_next_hops = ns.ip4_next_hops[:0]
		}
		ip_nh.ip4_nhs = ns.ip4_next_hops
		ip_nh.is_ip4 = true
	} else if family == syscall.AF_INET6 {
		if ns.ip6_next_hops != nil {
			ns.ip6_next_hops = ns.ip6_next_hops[:0]
		}
		ip_nh.ip6_nhs = ns.ip6_next_hops
		ip_nh.is_ip4 = false
	}

	if ns == nil {
		dbgfdb.Fib.Log("ns is nil")
	} else {
		dbgfdb.Fib.Log("ns is", ns.name)
	}
	xethNhs := msg.NextHops()
	dbgfdb.Fib.Log(len(xethNhs), "nexthops")
	for i, _ := range xethNhs {
		dbgfdb.Fib.Logf("nexthops[%d]: %#v", i, xethNhs[i])
	}

	if len(xethNhs) == 1 {
		ret := ProcessSingleIpNexthop(ns, xethNhs[0], ip_nh)
		if ret != nil {
			//err log or panic
		}
	} else {
		ProcessMultipleIpNexthops(ns, xethNhs, ip_nh)
	}

	if family == syscall.AF_INET {
		ns.ip4_next_hops = ip_nh.ip4_nhs // save for next call
	} else if family == syscall.AF_INET6 {
		ns.ip6_next_hops = ip_nh.ip6_nhs // save for next call
	}
	return
}

//TBDIP6: PRG
func (ns *net_namespace) parseIP6NextHops(msg *xeth.MsgFibentry) (nhs []ip6_next_hop) {
	if ns.ip6_next_hops != nil {
		ns.ip6_next_hops = ns.ip6_next_hops[:0]
	}
	nhs = ns.ip6_next_hops

	if ns == nil {
		dbgfdb.Fib.Log("ns is nil")
	} else {
		dbgfdb.Fib.Log("ns is", ns.name)
	}
	xethNhs := msg.NextHops()
	dbgfdb.Fib.Log(len(xethNhs), "nexthops")
	for i, _ := range xethNhs {
		dbgfdb.Fib.Logf("nexthops[%d]: %#v", i, xethNhs[i])
	}

	// If only 1 nh then assume this is single OIF nexthop
	// otherwise it's multipath
	nh := ip6_next_hop{}
	nh.Weight = 1
	if len(xethNhs) == 1 {
		nh.intf = ns.interface_by_index[uint32(xethNhs[0].Ifindex)]
		if nh.intf == nil {
			dbgfdb.Fib.Log("no ns-intf for ifindex",
				xethNhs[0].Ifindex)
			return
		}
		nh.Si = nh.intf.si
		copy(nh.Address[:], xethNhs[0].IP())
		nhs = append(nhs, nh)
	} else {
		for _, xnh := range xethNhs {
			intf := ns.interface_by_index[uint32(xnh.Ifindex)]
			if intf == nil {
				dbgfdb.Fib.Log("no ns-intf for ifindex",
					xnh.Ifindex)
				continue
			}
			nh.Si = intf.si
			nh.Weight = ip.NextHopWeight(xnh.Weight)
			if nh.Weight == 0 {
				nh.Weight = 1
			}
			copy(nh.Address[:], xnh.IP())
			nhs = append(nhs, nh)
		}
	}
	ns.ip6_next_hops = nhs // save for next call
	return
}

func ProcessIpNeighbor(msg *xeth.MsgNeighUpdate, v *vnet.Vnet) (err error) {

	// For now only doing IPv4
	if msg.Family != syscall.AF_INET {
		dbgfdb.Neigh.Log("msg:", msg, "not actioned because not IPv4")
		return
	}
	if msg.Net == 1 && msg.Ifindex == 2 {
		// ignore eth0 in netns default
		return
	}

	kind := xeth.Kind(msg.Kind)
	netns := xeth.Netns(msg.Net)
	dbgfdb.Neigh.Log(kind, "netns:", netns, "family:", msg.Family)
	var macIsZero bool = true
	for _, i := range msg.Lladdr {
		if i != 0 {
			macIsZero = false
			break
		}
	}
	isDel := macIsZero
	m := GetMain(v)
	ns := getNsByInode(m, msg.Net)
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	addr := msg.CloneIP() // this makes a net.IP out of msg.Dst
	if ns == nil {
		dbgfdb.Ns.Log("namespace", netns, "not found")
		if !lo.Contains(addr) {
			dbgfdb.Neigh.Log("INFO", vnet.IsDel(isDel).String(), "msg:", msg, "not actioned because namespace", netns, "not found")
		}
		return
	}
	si, ok := ns.siForIfIndex(uint32(msg.Ifindex))
	if !ok {
		//dbgfdb.Neigh.Log("no si for", msg.Ifindex, "in", ns.name)
		// Ifindex 2 is eth0
		if !lo.Contains(addr) && msg.Ifindex != 2 {
			dbgfdb.Neigh.Log("INFO", vnet.IsDel(isDel).String(), "msg", msg, "not actioned because no si for", msg.Ifindex, "in", ns.name)
		}
		return
	}

	// Don't enable bridge feature yet
	// FIXME, REMOVEME if enabling bridge
	if !AllowBridge && si.Kind(v) == vnet.SwBridgeInterface {
		dbgfdb.Neigh.Log("Ignore, for now,  bridge neighbor for ", vnet.SiName{V: v, Si: si}, "in", ns.name)
		return
	}

	dbgfdb.Neigh.Logf("msg.Dst %v ip %v %v\n", msg.Dst, addr, vnet.SiName{V: v, Si: si})
	nbr := ethernet.IpNeighbor{
		Si:       si,
		Ethernet: ethernet.Address(msg.Lladdr),
		Ip:       addr,
	}
	m4 := ip4.GetMain(v)
	em := ethernet.GetMain(v)
	dbgfdb.Neigh.Log(vnet.IsDel(isDel).String(), "nbr", nbr)
	_, err = em.AddDelIpNeighbor(&m4.Main, &nbr, isDel)

	// Ignore delete of unknown neighbor.
	if err == ethernet.ErrDelUnknownNeighbor {
		err = nil
	}
	return
}

func ProcessIp6Neighbor(msg *xeth.MsgNeighUpdate, v *vnet.Vnet) (err error) {
	// For now only doing IPv6
	if msg.Family != syscall.AF_INET6 {
		return
	}

	kind := xeth.Kind(msg.Kind)
	dbgfdb.Neigh.Log(kind)
	var macIsZero bool = true
	for _, i := range msg.Lladdr {
		if i != 0 {
			macIsZero = false
			break
		}
	}
	isDel := macIsZero
	m := GetMain(v)
	ns := getNsByInode(m, msg.Net)
	netns := xeth.Netns(msg.Net)
	if ns == nil {
		dbgfdb.Ns.Log("namespace", netns, "not found")
		return
	}
	si, ok := ns.siForIfIndex(uint32(msg.Ifindex))
	if !ok {
		dbgfdb.Neigh.Log("no si for", msg.Ifindex, "in", ns.name)
		return
	}
	nbr := ethernet.IpNeighbor{
		Si:       si,
		Ethernet: ethernet.Address(msg.Lladdr),
		Ip:       ip.Address(msg.Dst),
	}
	m6 := ip6.GetMain(v)
	em := ethernet.GetMain(v)
	dbgfdb.Neigh.Log(vnet.IsDel(isDel), "nbr", nbr)
	_, err = em.AddDelIpNeighbor(&m6.Main, &nbr, isDel)

	// Ignore delete of unknown neighbor.
	if err == ethernet.ErrDelUnknownNeighbor {
		err = nil
	}
	return
}

// Zero Gw processing covers 2 major sub-cases:
// 1. Interface-address setting
//    If local table entry and is a known interface of vnet i.e. front-panel then
//    install an interface address
// 2. Dummy or any other interface that's not a front panel or vlans of a front panel setting
//    If not a known interface of vnet, we assume it's a dummy and install as a punt
//    adjacency (FIXME - need to filter routes through eth0 and others)
func ProcessZeroGw(msg *xeth.MsgFibentry, v *vnet.Vnet, ns *net_namespace, isDel, isLocal, isMainUc bool) (err error) {
	xethNhs := msg.NextHops()
	pe, _ := vnet.Ports.GetPortByIndex(xethNhs[0].Ifindex)
	si, ok := ns.siForIfIndex(uint32(xethNhs[0].Ifindex))
	if pe != nil && !ok {
		// found a port entry but no si for it; not expected
		dbgfdb.Fib.Log("INFO found port entry but no si, pe = ", pe)
	}
	if pe != nil && ok {
		// Adds (local comes first followed by main-uc):
		// If local-local route then stash /32 prefix into Port[] table
		// If main-unicast route then lookup port in Port[] table and marry
		// local prefix and main-unicast prefix-len to install interface-address
		// Dels (main-uc comes first followed by local):
		//
		m := GetMain(v)
		ns := getNsByInode(m, pe.Net)
		if ns == nil {
			dbgfdb.Ns.Log("namespace", pe.Net, "not found")
			dbgfdb.Fib.Log("INFO", vnet.IsDel(isDel).String(), "msg:", msg, "not actioned because namespace", xeth.Netns(pe.Net), "not found")
			return
		}
		dbgfdb.Ns.Log("namespace", pe.Net, "found")
		if ok {
			m4 := ip4.GetMain(v)
			if isLocal {
				dbgfdb.Fib.Log(vnet.IsDel(isDel).String(), "local", msg.Prefix(), "ifindex", xethNhs[0].Ifindex, "si", si, vnet.SiName{V: v, Si: si}, si.Kind(v), si.GetType(v))
				m4.AddDelInterfaceAddressRoute(msg.Prefix(), si, ip4.LOCAL, isDel)
			} else if isMainUc {
				dbgfdb.Fib.Log(vnet.IsDel(isDel).String(), "main", msg.Prefix(), "ifindex", xethNhs[0].Ifindex, "si", si, vnet.SiName{V: v, Si: si}, si.Kind(v), si.GetType(v))
				m4.AddDelInterfaceAddressRoute(msg.Prefix(), si, ip4.GLEAN, isDel)
			} else {
				dbgfdb.Fib.Log(vnet.IsDel(isDel).String(),
					"neither local nor main", msg.Prefix(), vnet.SiName{V: v, Si: si})
			}
		}
	} else {
		// punt for any other interface not a front-panel or vlans on a front-panel
		dbgfdb.Fib.Log("Non-front-panel", vnet.IsDel(isDel).String(), "punt for", msg.Prefix(), "ifindex", xethNhs[0].Ifindex)
		m4 := ip4.GetMain(v)
		in := msg.Prefix()
		var addr ip4.Address
		for i := range in.IP {
			addr[i] = in.IP[i]
		}
		// Filter 127.*.*.* routes
		if addr[0] == 127 {
			return
		}
		adj := ip.AdjPunt
		if xethNhs[0].Ifindex == 0 {
			adj = ip.AdjDrop
		}
		m4.AddDelRoute(in, ns.fibIndexForNamespace(), adj, isDel)
	}
	return
}

func ProcessIp6ZeroGw(msg *xeth.MsgFibentry, v *vnet.Vnet, ns *net_namespace, isDel, isLocal, isMainUc bool) (err error) {
	xethNhs := msg.NextHops()
	pe := vnet.GetPortByIndex(xethNhs[0].Ifindex)
	if pe != nil {
		// Adds (local comes first followed by main-uc):
		// If local-local route then stash /32 prefix into Port[] table
		// If main-unicast route then lookup port in Port[] table and marry
		// local prefix and main-unicast prefix-len to install interface-address
		// Dels (main-uc comes first followed by local):
		//
		m := GetMain(v)
		ns := getNsByInode(m, pe.Net)
		if ns == nil {
			dbgfdb.Ns.Log("namespace", pe.Net, "not found")
			return
		}
		dbgfdb.Ns.Log("namespace", pe.Net, "found")
		if isLocal {
			dbgfdb.Fib.Log(vnet.IsDel(isDel).String(), "local", msg.Prefix())
		} else if isMainUc {
			dbgfdb.Fib.Log(vnet.IsDel(isDel).String(), "main", msg.Prefix())
			//m4 := ip4.GetMain(v)
			//ns.Ip4IfaddrMsg(m4, msg.Prefix(), uint32(xethNhs[0].Ifindex), isDel)
		} else {
			dbgfdb.Fib.Log(vnet.IsDel(isDel),
				"neither local nor main", msg.Prefix())
		}
	} else {
		// dummy processing
		if isLocal {
			dbgfdb.Fib.Log("dummy install punt for", msg.Prefix())
			m6 := ip6.GetMain(v)
			in := msg.Prefix()
			var addr ip6.Address
			for i := range in.IP {
				addr[i] = in.IP[i]
			}
			//TBDIP6: whats the ip6 equivalent of 127.0.0.0?
			//seems like ::1/128
			// Filter 127.*.*.* routes
			if addr[0] == 0 && addr[len(addr)-1] == 1 {
				return
			}

			p := ip6.Prefix{Address: addr, Len: 128}
			q := p.ToIpPrefix()
			m6.AddDelRoute(&q, ns.fibIndexForNamespace(), ip.AdjPunt, isDel)
		}
	}
	return
}

//func addrIsZero(addr net.IP) bool {
func addrIsZero(addr net.IP) bool {
	var aiz bool = true
	for _, i := range addr {
		if i != 0 {
			aiz = false
			break
		}
	}
	return aiz
}

func addrIsZeroHelper(addr ip.Address) bool {
	var aiz bool = true
	for _, i := range addr {
		if i != 0 {
			aiz = false
			break
		}
	}
	return aiz
}

func ip6addrIsZero(addr ip6.Address) bool {
	var aiz bool = true
	for _, i := range addr {
		if i != 0 {
			aiz = false
			break
		}
	}
	return aiz
}

/* TBDIP6: helper method to perform common functionality of ip4/ip6
 */
func ProcessZeroGwHelper(msg *xeth.MsgFibentry, v *vnet.Vnet, ns *net_namespace, is_ip4, isDel, isLocal, isMainUc bool) (err error) {
	xethNhs := msg.NextHops()
	pe := vnet.GetPortByIndex(xethNhs[0].Ifindex)
	if pe != nil {
		// Adds (local comes first followed by main-uc):
		// If local-local route then stash /32 prefix into Port[] table
		// If main-unicast route then lookup port in Port[] table and marry
		// local prefix and main-unicast prefix-len to install interface-address
		// Dels (main-uc comes first followed by local):
		//
		m := GetMain(v)
		ns := getNsByInode(m, pe.Net)
		if ns == nil {
			dbgfdb.Ns.Log("namespace", pe.Net, "not found")
			return
		}
		dbgfdb.Ns.Log("namespace", pe.Net, "found")
		if isLocal {
			dbgfdb.Fib.Log(vnet.IsDel(isDel).String(), "local", msg.Prefix())
		} else if isMainUc {
			dbgfdb.Fib.Log(vnet.IsDel(isDel).String(), "main", msg.Prefix())
			//m4 := ip4.GetMain(v)
			//ns.Ip4IfaddrMsg(m4, msg.Prefix(), uint32(xethNhs[0].Ifindex), isDel)
		} else {
			dbgfdb.Fib.Log(vnet.IsDel(isDel).String(),
				"neither local nor main", msg.Prefix())
		}
	} else {
		// dummy processing
		if isLocal {
			dbgfdb.Fib.Log("dummy install punt for", msg.Prefix())
			in := msg.Prefix()
			var addr ip.Address
			for i := range in.IP {
				addr[i] = in.IP[i]
			}
			//TBDIP6: whats the ip6 equivalent of 127.0.0.0?
			//seems like ::1/128
			// Filter 127.*.*.* routes
			if is_ip4 {
				if addr[0] == 127 {
					return
				}
				var p ip4.Prefix
				copy(p.Address[:], addr[:len(p.Address)])
				p.Len = 32
				q := p.ToIpPrefix()
				m4 := ip4.GetMain(v)
				m4.AddDelRoute(&q, ns.fibIndexForNamespace(), ip.AdjPunt, isDel)
			} else {
				if addr[0] == 0 && addr[len(addr)-1] == 1 {
					return
				}
				var p ip6.Prefix
				copy(p.Address[:], addr[:len(p.Address)])
				p.Len = 128
				q := p.ToIpPrefix()
				m6 := ip6.GetMain(v)
				m6.AddDelRoute(&q, ns.fibIndexForNamespace(), ip.AdjPunt, isDel)
			}
		}
	}
	return
}

/* TBDIP6: PRG */
/*
func ProcessMultipleRouteNextHops(p *ip.Prefix, ip_nh ip_next_hops, family uint8, isDel, isReplace bool) {
	// TBDIP6:
	// options to iterate once for either ip4/ip6 nhs to avoid repeating code paths for ip4 and ip6
	// 1. create temp copy of nhs
	// 2. some how use interface{} to get a generic pointer
	// 3. define a generic type ip_cmn_next_hop that has all the fields of ip4_nh and ip6_nh and use family to copy
	// certain fields only into the new nh and pass it to other methods
	// 4. use reflection package?
	// 5. refer: AddDelIpNeighbor => use the main package to refer to family specific wrapper


	if family == syscall.AF_INET {
		ptr := unsafe.Pointer(&ip_nh.ip4_nhs[0])
	} else if family == syscall.AF_INET6 {
		ptr := unsafe.Pointer(&ip_nh.ip6_nhs[0])
	}
	for _, nh := range nhs {
		if addrIsZeroHelper(nh.Address) {
			// TBDIP6: call helper
			ProcessZeroGwHelper(fib_msg, v, nil, ip_nh.is_ip4, isDel, isLocal, isMainUc)
			return
		}

		dbgfdb.Fib.Log(addDelReplace(isDel, isReplace), "nexthop", nh.Address,
			"for", fib_msg.Prefix, "in", netns)
		if ip_nh.is_ip4 {
			m4 := ip4.GetMain(v)
			err = m4.AddDelRouteNextHop(&p, &nh.NextHop, isDel, isReplace)
		} else {
			m6 := ip6.GetMain(v)
			err = m6.AddDelRouteNextHop(&p, &nh.NextHop, isDel, isReplace)
		}
		if err != nil {
			dbgfdb.Fib.Log(err)
			return
		}
		//This flag should only be set once on first nh because it deletes any previously set nh
		isReplace = false
	}
}
*/

/* TBDIP6: helper method to perform common functionality of ip4/ip6
 * assumptions:
 * 1. caller passes msg of type ptr := unsafe.Pointer(&msg[0])
 * 2. ip6 fib entry message update is different from ip4 fib enty message
 */
func ProcessFibEntryHelper(msg []byte, family uint8, v *vnet.Vnet) (err error) {
	var ip_addr ip.Address

	ptr := unsafe.Pointer(&msg[0])
	fib_msg := (*xeth.MsgFibentry)(ptr)

	var isLocal bool = fib_msg.Id == xeth.RT_TABLE_LOCAL && fib_msg.Type == xeth.RTN_LOCAL
	var isMainUc bool = fib_msg.Id == xeth.RT_TABLE_MAIN && fib_msg.Type == xeth.RTN_UNICAST

	netns := xeth.Netns(fib_msg.Net)
	rtn := xeth.Rtn(fib_msg.Id)
	rtt := xeth.RtTable(fib_msg.Type)

	// fwiw netlink handling also filters RTPROT_KERNEL and RTPROT_REDIRECT
	if fib_msg.Type != xeth.RTN_UNICAST || fib_msg.Id != xeth.RT_TABLE_MAIN {
		if isLocal {
			dbgfdb.Fib.Log(rtn, "table", rtt, fib_msg.Prefix(),
				"in", netns)
		} else {
			dbgfdb.Fib.Log(nil, "ignore", rtn, "table", rtt,
				"in", netns)
			return
		}
	} else {
		dbgfdb.Fib.Log(rtn, "table", rtt, fib_msg.Prefix(), "in", netns)
	}

	isDel := fib_msg.Event == xeth.FIB_EVENT_ENTRY_DEL
	isReplace := fib_msg.Event == xeth.FIB_EVENT_ENTRY_REPLACE

	m := GetMain(v)
	ns := getNsByInode(m, fib_msg.Net)
	if ns == nil {
		dbgfdb.Ns.Log("namespace", netns, "not found")
		return
	}

	ip_nh := ns.parseIPNextHopsHelper(fib_msg, family)

	//common code for nhs
	/* single nh => absorbed in multiple nh case in for loop */
	/*
		if len(xethNhs) == 1 {
			var nhAddr ip.Address
			copy(nhAddr[:], xethNhs[0].IP())
			if addrIsZeroHelper(nhAddr) {
				// TBDIP6: call helper
				ProcessZeroGw(msg, v, ns, isDel, isLocal, isMainUc)
				return
			}
		}
	*/

	/* TBDIP6: duplicate code path for ip4 and ip6 for now  */
	// fix this after validating with the  xeth + vnet integration
	if ip_nh.is_ip4 {
		p := ipnetToIP4Prefix(fib_msg.Prefix())
		for _, nh := range ip_nh.ip4_nhs {
			copy(ip_addr[:], nh.Address[:])
			if addrIsZeroHelper(ip_addr) {
				// TBDIP6: call helper
				ProcessZeroGwHelper(fib_msg, v, nil, ip_nh.is_ip4, isDel, isLocal, isMainUc)
				return
			}

			dbgfdb.Fib.Log(addDelReplace(isDel, isReplace), "nexthop", nh.Address,
				"for", fib_msg.Prefix, "in", netns)
			m4 := ip4.GetMain(v)
			err = m4.AddDelRouteNextHop(&p, &nh.NextHop, isDel, isReplace)
			if err != nil {
				dbgfdb.Fib.Log(err)
				return
			}
			//This flag should only be set once on first nh because it deletes any previously set nh
			isReplace = false
		}
	} else {
		p := ipnetToIP6Prefix(fib_msg.Prefix())
		for _, nh := range ip_nh.ip6_nhs {
			copy(ip_addr[:], nh.Address[:])
			if addrIsZeroHelper(ip_addr) {
				// TBDIP6: call helper
				ProcessZeroGwHelper(fib_msg, v, nil, ip_nh.is_ip4, isDel, isLocal, isMainUc)
				return
			}

			dbgfdb.Fib.Log(addDelReplace(isDel, isReplace), "nexthop", nh.Address,
				"for", fib_msg.Prefix, "in", netns)
			m6 := ip6.GetMain(v)
			err = m6.AddDelRouteNextHop(&p, &nh.NextHop, isDel, isReplace)
			if err != nil {
				dbgfdb.Fib.Log(err)
				return
			}
			//This flag should only be set once on first nh because it deletes any previously set nh
			isReplace = false
		}
	}
	return nil
}

// NB:
// Using these tests you could replace interface-address message and just use
// fibentry - use this test for interface address routes
// 	if (msg.Id == xeth.RT_TABLE_LOCAL && msg.Type == xeth.RTN_LOCAL) ||
//		(msg.Id == xeth.RT_TABLE_MAIN && msg.Type == xeth.RTN_UNICAST) {
func ProcessFibEntry(msg *xeth.MsgFibentry, v *vnet.Vnet) (err error) {

	var isLocal bool = msg.Id == xeth.RT_TABLE_LOCAL && msg.Type == xeth.RTN_LOCAL
	var isMainUc bool = msg.Id == xeth.RT_TABLE_MAIN && msg.Type == xeth.RTN_UNICAST

	netns := xeth.Netns(msg.Net)
	rtn := xeth.Rtn(msg.Id)
	rtt := xeth.RtTable(msg.Type)
	dbgfdb.Fib.Log(msg)
	// fwiw netlink handling also filters RTPROT_KERNEL and RTPROT_REDIRECT
	if msg.Type != xeth.RTN_UNICAST || msg.Id != xeth.RT_TABLE_MAIN {
		if isLocal {
			dbgfdb.Fib.Log(rtn, "table", rtt, msg.Prefix(),
				"in", netns)
		} else {
			dbgfdb.Fib.Log(nil, "ignore", rtn, "table", rtt,
				"in", netns)
			if msg.Type == xeth.RTN_BLACKHOLE {
				dbgfdb.Fib.Log("blackhole")
			} else {
				return
			}
		}
	} else {
		dbgfdb.Fib.Log(rtn, "table", rtt, msg.Prefix(), "in", netns)
	}

	isDel := msg.Event == xeth.FIB_EVENT_ENTRY_DEL
	isReplace := msg.Event == xeth.FIB_EVENT_ENTRY_REPLACE

	m := GetMain(v)
	ns := getNsByInode(m, msg.Net)
	if ns == nil {
		dbgfdb.Ns.Log("namespace", netns, "not found")
		_, lo, _ := net.ParseCIDR("127.0.0.0/8")
		if !lo.Contains(msg.Prefix().IP) {
			dbgfdb.Fib.Log("INFO", vnet.IsDel(isDel).String(), "msg:", msg, "not actioned because namespace", xeth.Netns(msg.Net), "not found")
		}
		return
	}
	nhs := ns.parseIP4NextHops(msg) // this gets rid of next hops that are not xeth interfaces or interfaces built on xeth
	m4 := ip4.GetMain(v)

	xethNhs := msg.NextHops()
	// Check for dummy processing
	if len(xethNhs) == 1 {
		if addrIsZero(xethNhs[0].IP()) {
			ProcessZeroGw(msg, v, ns, isDel, isLocal, isMainUc)
			return
		}
	}

	// handle ipv4 only for now
	if a4 := msg.Prefix().IP.To4(); len(a4) == net.IPv4len && len(nhs) > 0 {
		m4.AddDelRouteNextHops(ns.fibIndexForNamespace(), msg.Prefix(), nhs, isDel, isReplace)
	}
	return
}

//TBDIP6: PRG
//TBDIP6: PRG
//-added ip6i equivalents
func ProcessIp6FibEntry(msg *xeth.MsgFibentry, v *vnet.Vnet) (err error) {

	var isLocal bool = msg.Id == xeth.RT_TABLE_LOCAL && msg.Type == xeth.RTN_LOCAL
	var isMainUc bool = msg.Id == xeth.RT_TABLE_MAIN && msg.Type == xeth.RTN_UNICAST

	netns := xeth.Netns(msg.Net)
	rtn := xeth.Rtn(msg.Id)
	rtt := xeth.RtTable(msg.Type)
	// fwiw netlink handling also filters RTPROT_KERNEL and RTPROT_REDIRECT
	if msg.Type != xeth.RTN_UNICAST || msg.Id != xeth.RT_TABLE_MAIN {
		if isLocal {
			dbgfdb.Fib.Log(rtn, "table", rtt, msg.Prefix(),
				"in", netns)
		} else {
			dbgfdb.Fib.Log(nil, "ignore", rtn, "table", rtt,
				"in", netns)
			return
		}
	} else {
		dbgfdb.Fib.Log(rtn, "table", rtt, msg.Prefix(), "in", netns)
	}

	isDel := msg.Event == xeth.FIB_EVENT_ENTRY_DEL
	isReplace := msg.Event == xeth.FIB_EVENT_ENTRY_REPLACE

	p := ipnetToIP6Prefix(msg.Prefix())

	m := GetMain(v)
	ns := getNsByInode(m, msg.Net)
	if ns == nil {
		dbgfdb.Ns.Log("namespace", netns, "not found")
		return
	}
	nhs := ns.parseIP6NextHops(msg)
	m6 := ip6.GetMain(v)

	dbgfdb.Fib.Log(len(nhs), "nexthops for", netns)

	// Check for dummy processing
	xethNhs := msg.NextHops()
	if len(xethNhs) == 1 {
		var nhAddr ip6.Address
		copy(nhAddr[:], xethNhs[0].IP())

		if ip6addrIsZero(nhAddr) {
			//TBDIP6: call ip6 specific method
			ProcessIp6ZeroGw(msg, v, ns, isDel, isLocal, isMainUc)
			return
		}

	}

	// Regular nexthop processing
	for _, nh := range nhs {
		if ip6addrIsZero(nh.Address) {
			//TBDIP6: call ip6 specific method
			ProcessIp6ZeroGw(msg, v, nil, isDel, isLocal, isMainUc)
			return
		}

		dbgfdb.Fib.Log(addDelReplace(isDel, isReplace), "nexthop", nh.Address,
			"for", msg.Prefix, "in", netns)

		err = m6.AddDelRouteNextHop(&p, &nh.NextHop, isDel, isReplace)
		if err != nil {
			dbgfdb.Fib.Log(err)
			return
		}
		//This flag should only be set once on first nh because it deletes any previously set nh
		isReplace = false
	}
	return
}

func (ns *net_namespace) Ip4IfaddrMsg(m4 *ip4.Main, ipnet *net.IPNet, ifindex uint32, isDel bool) (err error) {
	p := ipnetToIP4Prefix(ipnet)
	dbgfdb.Ifa.Log(ipnet, "-->", p)
	if si, ok := ns.siForIfIndex(ifindex); ok {
		dbgfdb.Ifa.Log(vnet.IsDel(isDel).String(), "si", si)
		ns.validateFibIndexForSi(si)
		err = m4.AddDelInterfaceAddress(si, p, isDel)
		dbgfdb.Ifa.Log(err)
	} else {
		dbgfdb.Ifa.Log("no si for ifindex:", ifindex)
	}
	return
}

func (ns *net_namespace) Ip6IfaddrMsg(m6 *ip6.Main, ipnet *net.IPNet, ifindex uint32, isDel bool) (err error) {
	p := ipnetToIP6Prefix(ipnet)
	dbgfdb.Ifa.Log(ipnet, "-->", p)
	if si, ok := ns.siForIfIndex(ifindex); ok {
		dbgfdb.Ifa.Log(vnet.IsDel(isDel), "si", si)
		ns.validateFibIndexForSi(si)
		err = m6.AddDelInterfaceAddress(si, &p, isDel)
		dbgfdb.Ifa.Log(err)
	} else {
		dbgfdb.Ifa.Log("no si for ifindex:", ifindex)
	}
	return
}

func ProcessInterfaceAddr(msg *xeth.MsgIfa, action vnet.ActionType, v *vnet.Vnet) (err error) {
	if msg == nil {
		sendFdbEventIfAddr(v)
		return
	}
	xethif := xeth.Interface.Indexed(msg.Ifindex)
	if xethif == nil {
		err = fmt.Errorf("can't find %d", msg.Ifindex)
		return
	}
	ifname := xethif.Name
	if len(ifname) == 0 {
		err = fmt.Errorf("interface %d has no name", msg.Ifindex)
		return
	}
	pe, found := vnet.Ports.GetPortByName(ifname)
	if !found {
		err = dbgfdb.Ifa.Log("ifname not found, ignored", action, msg.IsAdd(), ifname, msg.IPNet())
		return
	}

	ifaevent := xeth.IfaEvent(msg.Event)
	switch action {
	case vnet.PreVnetd:
		// stash addresses for later use
		dbgfdb.Ifa.Log("PreVnetd", ifaevent, msg.IPNet(), "to", ifname)
		if msg.IsAdd() {
			pe.AddIPNet(msg.IPNet())
		} else if msg.IsDel() {
			pe.DelIPNet(msg.IPNet())
		}
	case vnet.ReadyVnetd:
		// Walk Port map and flush any IFAs we gathered at prevnetd time
		dbgfdb.Ifa.Log("ReadyVnetd", ifaevent)
		sendFdbEventIfAddr(v)
	case vnet.PostReadyVnetd:
		dbgfdb.Ifa.Log("PostReadyVnetd", ifaevent)
		fallthrough
	case vnet.Dynamic:
		dbgfdb.Ifa.Log("Dynamic", ifaevent, msg)
		// vnetd is up and running and received an event, so call into vnet api
		pe, found := vnet.Ports.GetPortByName(ifname)
		if !found {
			err = fmt.Errorf("Dynamic IFA - %q unknown", ifname)
			dbgfdb.Ifa.Log(err)
			return
		}
		if FdbOn {
			if action == vnet.Dynamic {
				dbgfdb.Ifa.Log(ifname, ifaevent, msg.IPNet())
				if msg.IsAdd() {
					pe.AddIPNet(msg.IPNet())
				} else if msg.IsDel() {
					pe.DelIPNet(msg.IPNet())
				}
			}

			m := GetMain(v)
			ns := getNsByInode(m, pe.Net)
			if ns != nil {
				dbgfdb.Ns.Log("namespace", pe.Net, "found")
				m4 := ip4.GetMain(v)
				ns.Ip4IfaddrMsg(m4, msg.IPNet(), uint32(pe.Ifindex), msg.IsDel())
			} else {
				dbgfdb.Ns.Log("namespace", pe.Net, "not found")
				dbgfdb.Fib.Log("INFO msg:", msg, "not actioned because namespace", xeth.Netns(pe.Net), "not found")
			}
		}
	}
	return
}

func makeMsgIfa(xethif *xeth.InterfaceEntry, peipnet *net.IPNet) (buf []byte) {
	buf = xeth.Pool.Get(xeth.SizeofMsgIfa)
	msg := (*xeth.MsgIfa)(unsafe.Pointer(&buf[0]))
	msg.Kind = xeth.XETH_MSG_KIND_IFA
	msg.Ifindex = xethif.Index
	msg.Event = xeth.IFA_ADD
	msg.Address = ipnetToUint(peipnet, true)
	msg.Mask = ipnetToUint(peipnet, false)

	dbgfdb.Ifa.Log(xethif.Name, msg.IPNet())

	return
}

func ProcessInterfaceIp6Addr(msg *xeth.MsgIfa, action vnet.ActionType, v *vnet.Vnet) (err error) {
	if msg == nil {
		sendFdbEventIp6IfAddr(v)
		return
	}
	xethif := xeth.Interface.Indexed(msg.Ifindex)
	if xethif == nil {
		err = fmt.Errorf("can't find %d", msg.Ifindex)
		return
	}
	ifname := xethif.Name
	if len(ifname) == 0 {
		err = fmt.Errorf("interface %d has no name", msg.Ifindex)
		return
	}
	ifaevent := xeth.IfaEvent(msg.Event)
	switch action {
	case vnet.PreVnetd:
		// stash addresses for later use
		pe := vnet.SetPort(ifname)
		dbgfdb.Ifa.Log("PreVnetd", ifaevent, msg.IPNet(), "to", ifname)
		if msg.IsAdd() {
			pe.AddIPNet(msg.IPNet())
		} else if msg.IsDel() {
			pe.DelIPNet(msg.IPNet())
		}
	case vnet.ReadyVnetd:
		// Walk Port map and flush any IFAs we gathered at prevnetd time
		dbgfdb.Ifa.Log("ReadyVnetd", ifaevent)
		sendFdbEventIp6IfAddr(v)

		if false {
			m := GetMain(v)
			for _, pe := range vnet.Ports {
				ns := getNsByInode(m, pe.Net)
				if ns != nil {
					dbgfdb.Ifa.Log("ReadyVnetd namespace",
						pe.Net, pe.Ifname)
					m6 := ip6.GetMain(v)
					for _, peipnet := range pe.IPNets {
						ns.Ip6IfaddrMsg(m6, peipnet, uint32(pe.Ifindex), false)
					}
				} else {
					dbgfdb.Ns.Log("ReadyVnetd namespace",
						pe.Net, "not found")
				}
			}
		}

	case vnet.PostReadyVnetd:
		dbgfdb.Ifa.Log("PostReadyVnetd", ifaevent)
		fallthrough
	case vnet.Dynamic:
		dbgfdb.Ifa.Log("Dynamic", ifaevent)
		// vnetd is up and running and received an event, so call into vnet api
		pe, found := vnet.Ports[ifname]
		if !found {
			err = fmt.Errorf("Dynamic IFA - %q unknown", ifname)
			dbgfdb.Ifa.Log(err)
			return
		}
		if FdbOn {
			if action == vnet.Dynamic {
				dbgfdb.Ifa.Log(ifname, ifaevent, msg.IPNet())
				if msg.IsAdd() {
					pe.AddIPNet(msg.IPNet())
				} else if msg.IsDel() {
					pe.DelIPNet(msg.IPNet())
				}
			}

			m := GetMain(v)
			ns := getNsByInode(m, pe.Net)
			if ns != nil {
				dbgfdb.Ns.Log("namespace", pe.Net, "found")
				m6 := ip6.GetMain(v)
				ns.Ip6IfaddrMsg(m6, msg.IPNet(), uint32(pe.Ifindex), msg.IsDel())
			} else {
				dbgfdb.Ns.Log("namespace", pe.Net, "not found")
			}
		}
	}
}

func sendFdbEventIfAddr(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain
	fe := fdbm.GetEvent(vnet.PostReadyVnetd)

	vnet.Ports.Foreach(func(ifname string, pe *vnet.PortEntry) {
		xethif := xeth.Interface.Indexed(pe.Ifindex)
		for _, peipnet := range pe.IPNets {
			buf := makeMsgIfa(xethif, peipnet)
			ok := fe.EnqueueMsg(buf)
			if !ok {
				// filled event with messages so send event and start a new one
				fe.Signal()
				fe = fdbm.GetEvent(vnet.PostReadyVnetd)
				ok := fe.EnqueueMsg(buf)
				if !ok {
					panic("sendFdbEventIfAddr: Re-enqueue of msg failed")
				}
			}
		}
	})
	dbgfdb.Ifa.Log("sending", fe.NumMsgs, "messages")
	fe.Signal()
}

/* TBDIP6: ip6 version */
func sendFdbEventIp6IfAddr(v *vnet.Vnet) {
	/*
		m := GetMain(v)
		fdbm := &m.FdbMain
		fe := fdbm.GetEvent(vnet.PostReadyVnetd)

		for _, pe := range vnet.Ports {
			xethif := xeth.Interface.Indexed(pe.Ifindex)
			ifname := xethif.Name
			dbgfdb.Ifa.Log(ifname)

			for _, peipnet := range pe.IPNets {
				buf := xeth.Pool.Get(xeth.SizeofMsgIfa)
				msg := (*xeth.MsgIfa)(unsafe.Pointer(&buf[0]))
				msg.Kind = xeth.XETH_MSG_KIND_IFA
				msg.Ifindex = xethif.Index
				msg.Event = xeth.IFA_ADD
				msg.Address = ipnetToUint(peipnet, true)
				msg.Mask = ipnetToUint(peipnet, false)
				dbgfdb.Ifa.Log(ifname, msg.IPNet())
				ok := fe.EnqueueMsg(buf)
				if !ok {
					// filled event with messages so send event and start a new one
					fe.Signal()
					fe = fdbm.GetEvent(vnet.PostReadyVnetd)
					ok := fe.EnqueueMsg(buf)
					if !ok {
						panic("sendFdbEventIfAddr: Re-enqueue of msg failed")
					}
				}
			}
		}
		dbgfdb.Ifa.Log("sending", fe.NumMsgs, "messages")
		fe.Signal()
	*/
}

func pleaseDoAddNamepace(v *vnet.Vnet, net uint64) {
	// Ignore 1 which is default ns and created at init time
	if net == 1 {
		return
	}
	// First try and see if an existing namespace has this net number.
	// If so, just grab it. Otherwise, create a new one.
	m := GetMain(v)
	nm := &m.net_namespace_main
	if nsFound, ok := nm.namespace_by_inode[net]; ok {
		dbgfdb.Ns.Log(nsFound.name, "found for net", net)
	} else {
		name := strconv.FormatUint(net, 10)
		dbgfdb.Ns.Log("trying to add namespace", name)
		nm.addDelNamespace(name, false)
	}
}

// FIXME - need to add logic to handle a namespace that has been orphaned and needs
// to be cleaned out.
func maybeAddNamespaces(v *vnet.Vnet, net uint64) {
	// If specified find or create the namespace with inode-num "net".
	// Otherwise, we walk the PortEntry table and create namespaces
	// that we don't know about
	if net > 0 {
		dbgfdb.Ns.Log("add single ns for", net)
		pleaseDoAddNamepace(v, net)
	} else {
		// March through all port-entries.
		// If we haven't seen a Net before we need to create a net_namespace
		vnet.Ports.Foreach(func(ifname string, pe *vnet.PortEntry) {
			dbgfdb.Ns.Log("ReadyVnetd add", pe.Net, "for", pe.Ifname)
			pleaseDoAddNamepace(v, pe.Net)
		})
	}
}

func getNsByInode(m *Main, netNum uint64) *net_namespace {
	if netNum == 1 {
		return &m.default_namespace
	} else {
		return m.namespace_by_inode[netNum]
	}
}

var eth1, eth2 *net.Interface

func makePortEntry(msg *xeth.MsgIfinfo) (pe *vnet.PortEntry) {
	var err error

	if eth1 == nil || eth2 == nil {
		for _, name := range []string{"eth1", "enp3s0f0"} {
			eth1, err = net.InterfaceByName(name)
			if err == nil {
				break
			}
		}
		if err != nil {
			dbgfdb.XethMsg.Log(err)
			return
		}
		for _, name := range []string{"eth2", "enp3s0f1"} {
			eth2, err = net.InterfaceByName(name)
			if err == nil {
				break
			}
		}
		if err != nil {
			dbgfdb.XethMsg.Log(err)
			return
		}
	}

	ifname := xeth.Ifname(msg.Ifname)

	switch msg.Devtype {
	case xeth.XETH_DEVTYPE_XETH_PORT:
		pe = vnet.Ports.SetPort(ifname.String())
		pe.Portindex = msg.Portindex
		// -1 is unspecified - from driver
		if msg.Subportindex >= 0 {
			pe.Subportindex = msg.Subportindex
		}
		pe.PortVid = msg.Id
		// convert eth1/eth2 to meth-0/meth-1
		switch msg.Iflinkindex {
		case int32(eth1.Index):
			pe.PuntIndex = 0
		case int32(eth2.Index):
			pe.PuntIndex = 1
		}

	case xeth.XETH_DEVTYPE_LINUX_VLAN_BRIDGE_PORT:
		fallthrough
	case xeth.XETH_DEVTYPE_LINUX_VLAN:
		xp, _ := vnet.Ports.GetPortByIndex(msg.Iflinkindex)
		if xp == nil {
			dbgfdb.XethMsg.Logf("vlan no link %v %v", msg.Ifindex, msg.Iflinkindex)
		} else {
			pe = vnet.Ports.SetPort(ifname.String())
			pe.PortVid = xp.PortVid
			pe.Portindex = msg.Portindex
			// -1 is unspecified - from driver
			if msg.Subportindex >= 0 {
				pe.Subportindex = msg.Subportindex
			}
			pe.Ctag = msg.Id
		}
	case xeth.XETH_DEVTYPE_LINUX_BRIDGE:
		if AllowBridge {
			pe = ethernet.SetBridge(msg.Id, ifname.String())
			pe.PuntIndex = uint8(pe.Stag & 1)
		}
	}
	if pe == nil {
		dbgfdb.XethMsg.Logf("%v ignored, type=%v", ifname.String(), msg.Devtype)
		return
	}
	pe.Devtype = msg.Devtype
	pe.Ifname = ifname.String()
	pe.Net = msg.Net
	pe.Ifindex = msg.Ifindex
	pe.Iflinkindex = msg.Iflinkindex
	vnet.Ports.SetPortByIndex(msg.Ifindex, pe.Ifname)
	pe.Iff = net.Flags(msg.Flags)
	copy(pe.StationAddr, msg.Addr[:])

	dbgfdb.XethMsg.Logf("make(%v,%v) %v ifindex %v, iflinkindex %v, mac %v, punt %v",
		msg.Devtype, xeth.DevType(msg.Devtype).String(), ifname.String(),
		msg.Ifindex, msg.Iflinkindex, pe.StationAddr, pe.PuntIndex)

	return
}

func ProcessInterfaceInfo(msg *xeth.MsgIfinfo, action vnet.ActionType, v *vnet.Vnet) (err error) {
	if msg == nil {
		sendFdbEventIfInfo(v)
		return
	}

	netAddr := make(net.HardwareAddr, 6)
	copy(netAddr, msg.Addr[:])

	kind := xeth.Kind(msg.Kind)
	ifname := (*xeth.Ifname)(&msg.Ifname).String()
	ifindex := uint32(msg.Ifindex)
	reason := xeth.IfinfoReason(msg.Reason)
	netns := xeth.Netns(msg.Net)

	dbgfdb.Ifinfo.Log(action, ifname, ifindex, msg.Devtype)
	if msg.Devtype == xeth.XETH_DEVTYPE_LINUX_VLAN {
		/* disallow specific VLAN ID configs for vlan interfaces
		 */
		if msg.Id >= UNSUPPORTED_VLAN_CTAG_RANGE_MIN &&
			msg.Id <= UNSUPPORTED_VLAN_CTAG_RANGE_MAX {
			dbgfdb.Ifinfo.Log("%v.%v ignored, vlan range %v-%v is reserved",
				msg.Id, ifname,
				UNSUPPORTED_VLAN_CTAG_RANGE_MIN, UNSUPPORTED_VLAN_CTAG_RANGE_MAX)
			return
		}
	}

	switch action {
	case vnet.PreVnetd:
		makePortEntry(msg)
		dbgfdb.Ifinfo.Log("Prevnetd", kind, "makePortEntry", "Ifindex:", msg.Ifindex, "IfName:", ifname, "DevType:", xeth.DevType(msg.Devtype).String())

	case vnet.ReadyVnetd: // not reached
		// Walk Port map and flush into vnet/fe layers the interface info we gathered
		// at prevnetd time. Both namespace and interface creation messages sent during this processing.
		dbgfdb.Ifinfo.Log("ReadyVnetd add", ifname)
		// Signal that all namespaces are now initialized??
		sendFdbEventIfInfo(v)

	case vnet.PostReadyVnetd:
		fallthrough
	case vnet.Dynamic:
		m := GetMain(v)
		ns := getNsByInode(m, msg.Net)
		if ns == nil {
			dbgfdb.Ns.Log("namespace", netns, "not found")
			dbgfdb.Ifinfo.Log("INFO msg:", msg, "not actioned because namespace", xeth.Netns(msg.Net), "not found")
			return
		}
		dbgfdb.Ifinfo.Log("dynamic", reason.String(), kind, netns, ifname, ns.name, msg.Devtype, netAddr)

		pe, _ := vnet.Ports.GetPortByIndex(msg.Ifindex)
		if pe == nil {
			// If a vlan or bridge interface we allow dynamic creation so create a cached entry
			if msg.Devtype >= xeth.XETH_DEVTYPE_LINUX_UNKNOWN {
				pe = makePortEntry(msg)
			}
		}

		if pe == nil {
			dbgfdb.Ifinfo.Log("pe is nil - returning")
			return
		}
		if msg.Net != pe.Net {
			// This ifindex has been set into a new namespace so
			// 1. Remove ifindex from previous namespace
			// 2. Add ifindex to new namespace
			nsOld := getNsByInode(m, pe.Net)
			if nsOld == nil {
				// old namespace already removed
				dbgfdb.Ns.Log("Couldn't find old ns:", pe.Net)
			} else {
				nsOld.addDelMk1Interface(m, true, ifname,
					uint32(msg.Ifindex), netAddr, msg.Devtype, msg.Iflinkindex, msg.Id)
			}

			ns.addDelMk1Interface(m, false, ifname,
				uint32(msg.Ifindex), netAddr, msg.Devtype, msg.Iflinkindex, msg.Id)

			dbgfdb.Ifinfo.Log("moving", ifname, pe.Net, netns)
			pe.Net = msg.Net
		} else if action == vnet.PostReadyVnetd {
			// Goes has restarted with interfaces already in existent namespaces,
			// so create vnet representation of interface in this ns.
			// Or this is a dynamically created vlan interface.
			dbgfdb.Ifinfo.Log(ifname, netns)
			ns.addDelMk1Interface(m, false, ifname,
				uint32(msg.Ifindex), netAddr, msg.Devtype,
				msg.Iflinkindex, msg.Id)
		} else if msg.Devtype >= xeth.XETH_DEVTYPE_LINUX_UNKNOWN {
			// create or delete interfaces based on reg/unreg reason
			dbgfdb.Ifinfo.Log(ifname, reason, msg.Devtype, netns)
			if reason == xeth.XETH_IFINFO_REASON_REG {
				ns.addDelMk1Interface(m, false, ifname,
					uint32(msg.Ifindex), netAddr, msg.Devtype,
					msg.Iflinkindex, msg.Id)
			} else if reason == xeth.XETH_IFINFO_REASON_UNREG {
				ns.addDelMk1Interface(m, true, ifname,
					uint32(msg.Ifindex), netAddr, msg.Devtype,
					msg.Iflinkindex, msg.Id)
				if msg.Devtype == xeth.XETH_DEVTYPE_LINUX_BRIDGE {
					ethernet.UnsetBridge(pe.Stag)
				} else {
					vnet.Ports.UnsetPort(ifname)
				}
				return
			}
		}
		if ns.interface_by_index[ifindex] != nil {
			// Process admin-state flags
			if si, ok := ns.siForIfIndex(ifindex); ok {
				ns.validateFibIndexForSi(si)
				flags := net.Flags(msg.Flags)
				isUp := flags&net.FlagUp == net.FlagUp
				err = si.SetAdminUp(v, isUp)
				dbgfdb.Ifinfo.Log("SetAdminUp", si, msg.Devtype, isUp, err)
			} else {
				dbgfdb.Si.Log("can't get si of", ifname)
			}
		} else {
			// NB: This is the dynamic front-panel-port-creation case which our lower layers
			// don't support yet. Driver does not send us these but here as a placeholder.
			dbgfdb.Ifinfo.Log("Attempting dynamic port-creation of", ifname)
			if false {
				if action == vnet.Dynamic {
					_, found := vnet.Ports.GetPortByName(ifname)
					if !found {
						pe := vnet.Ports.SetPort(ifname)
						dbgfdb.Ifinfo.Log("setting",
							ifname, "in", netns)
						pe.Net = msg.Net
						pe.Ifindex = msg.Ifindex
						pe.Iflinkindex = msg.Iflinkindex
						pe.Ifname = ifname
						vnet.Ports.SetPortByIndex(msg.Ifindex, pe.Ifname)
						pe.Iff = net.Flags(msg.Flags)
						pe.PortVid = msg.Id
						copy(pe.StationAddr, msg.Addr[:])
						pe.Portindex = msg.Portindex
						pe.Subportindex = msg.Subportindex
						pe.PuntIndex = 0
					}
				}
				ns.addDelMk1Interface(m, false, ifname,
					uint32(msg.Ifindex), netAddr,
					msg.Devtype, msg.Iflinkindex,
					msg.Id)
			}
		}
	}
	return nil
}

func makeMsgIfinfo(entry *xeth.InterfaceEntry) (buf []byte) {
	dbgfdb.Ifinfo.Log(entry.Name, entry.Index, entry.Link)

	buf = xeth.Pool.Get(xeth.SizeofMsgIfinfo)
	msg := (*xeth.MsgIfinfo)(unsafe.Pointer(&buf[0]))
	msg.Kind = xeth.XETH_MSG_KIND_IFINFO
	copy(msg.Ifname[:], entry.Name)
	msg.Ifindex = entry.Index
	msg.Iflinkindex = entry.Link
	copy(msg.Addr[:], entry.HardwareAddr())
	msg.Net = uint64(entry.Netns)
	msg.Id = entry.Id
	msg.Portindex = entry.Port
	msg.Subportindex = entry.Subport
	msg.Flags = uint32(entry.Flags)
	msg.Devtype = uint8(entry.DevType)
	return
}

func makeMsgChangeUpper(lower, upper int32) (buf []byte) {
	dbgfdb.Ifinfo.Log(lower, upper)

	buf = xeth.Pool.Get(xeth.SizeofMsgChangeUpper)
	msg := (*xeth.MsgChangeUpper)(unsafe.Pointer(&buf[0]))
	msg.Kind = xeth.XETH_MSG_KIND_CHANGE_UPPER
	msg.Lower = lower
	msg.Upper = upper
	msg.Linking = 1
	return
}

// send XETH_PORT first to ensure (ifindex port) enqueued before (ifindex vlan-interface) which refs port via iflinkindex
func sendFdbEventIfInfo(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain
	fe := fdbm.GetEvent(vnet.PostReadyVnetd)

	for _, i := range [2]bool{false, true} {
		xeth.Interface.Iterate(func(entry *xeth.InterfaceEntry) error {
			if qualify := entry.DevType == xeth.XETH_DEVTYPE_XETH_PORT; !i && !qualify || i && qualify {
				return nil
			}
			buf := makeMsgIfinfo(entry)
			ok := fe.EnqueueMsg(buf)
			if !ok {
				// filled event with messages so send event and start a new one
				fe.Signal()
				fe = fdbm.GetEvent(vnet.PostReadyVnetd)
				ok := fe.EnqueueMsg(buf)
				if !ok {
					panic("sendFdbEventIfInfo: Re-enqueue of msg failed")
				}
			}
			return nil
		})
	}

	xeth.Interface.Iterate(func(entry *xeth.InterfaceEntry) error {
		entry.Uppers.Range(func(key, value interface{}) bool {
			buf := makeMsgChangeUpper(entry.Index, key.(int32))
			ok := fe.EnqueueMsg(buf)
			if !ok {
				// filled event with messages so send event and start a new one
				fe.Signal()
				fe = fdbm.GetEvent(vnet.PostReadyVnetd)
				ok := fe.EnqueueMsg(buf)
				if !ok {
					panic("sendFdbEventIfInfo: Re-enqueue of msg failed")
				}
			}
			return true
		})
		return nil
	})

	fe.Signal()
}

func ipnetToUint(ipnet *net.IPNet, ipNotMask bool) uint32 {
	if ipNotMask {
		return *(*uint32)(unsafe.Pointer(&ipnet.IP[0]))
	} else {
		return *(*uint32)(unsafe.Pointer(&ipnet.Mask[0]))
	}
}

func InitInterfaceEthtool(v *vnet.Vnet) {
	sendFdbEventEthtoolSettings(v)
	sendFdbEventEthtoolFlags(v)
}

func sendFdbEventEthtoolSettings(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain
	fe := fdbm.GetEvent(vnet.PostReadyVnetd)
	vnet.Ports.Foreach(func(ifname string, pe *vnet.PortEntry) {
		xethif := xeth.Interface.Indexed(pe.Ifindex)
		ifindex := xethif.Ifinfo.Index
		ifname = xethif.Ifinfo.Name
		if xethif.Ifinfo.DevType != xeth.XETH_DEVTYPE_XETH_PORT {
			return
		}
		dbgfdb.Ifinfo.Log(ifname, pe)
		buf := xeth.Pool.Get(xeth.SizeofMsgEthtoolSettings)
		msg := (*xeth.MsgEthtoolSettings)(unsafe.Pointer(&buf[0]))
		msg.Kind = xeth.XETH_MSG_KIND_ETHTOOL_SETTINGS
		msg.Ifindex = ifindex
		msg.Speed = uint32(pe.Speed)
		msg.Autoneg = pe.Autoneg
		// xeth layer is cacheing the rest of this message
		// in future can just reference that and send it along here
		ok := fe.EnqueueMsg(buf)
		if !ok {
			// filled event with messages so send event and start a new one
			fe.Signal()
			fe = fdbm.GetEvent(vnet.PostReadyVnetd)
			ok := fe.EnqueueMsg(buf)
			if !ok {
				panic("sendFdbEventEthtoolSettings: Re-enqueue of msg failed")
			}
		}
	})
	fe.Signal()
}

func sendFdbEventEthtoolFlags(v *vnet.Vnet) {
	m := GetMain(v)
	fdbm := &m.FdbMain
	fe := fdbm.GetEvent(vnet.PostReadyVnetd)
	vnet.Ports.Foreach(func(ifname string, pe *vnet.PortEntry) {
		xethif := xeth.Interface.Indexed(pe.Ifindex)
		ifindex := xethif.Ifinfo.Index
		ifname = xethif.Ifinfo.Name
		if xethif.Ifinfo.DevType != xeth.XETH_DEVTYPE_XETH_PORT {
			return
		}
		dbgfdb.Ifinfo.Log(ifname, pe)
		buf := xeth.Pool.Get(xeth.SizeofMsgEthtoolFlags)
		msg := (*xeth.MsgEthtoolFlags)(unsafe.Pointer(&buf[0]))
		msg.Kind = xeth.XETH_MSG_KIND_ETHTOOL_FLAGS
		msg.Ifindex = ifindex
		msg.Flags = uint32(pe.Flags)
		// xeth layer is cacheing the rest of this message
		// in future can just reference that and send it along here
		ok := fe.EnqueueMsg(buf)
		if !ok {
			// filled event with messages so send event and start a new one
			fe.Signal()
			fe = fdbm.GetEvent(vnet.PostReadyVnetd)
			ok := fe.EnqueueMsg(buf)
			if !ok {
				panic("sendFdbEventEthtoolFlags: Re-enqueue of msg failed")
			}
		}
	})
	fe.Signal()
}

func addDelReplace(isDel, isReplace bool) string {
	if isReplace {
		return "replace"
	} else if isDel {
		return "del"
	}
	return "add"
}

func (ns *net_namespace) ShowMsgNextHops(xethNhs []xeth.NextHop) (s string) {
	for _, xnh := range xethNhs {
		intf := ns.interface_by_index[uint32(xnh.Ifindex)]
		intfName := "nil"
		if intf != nil {
			intfName = intf.name
		}
		s += fmt.Sprintf("Intf %v; Weight %v; Flags %v; Gw %v; Scope %v; Pad %v\n",
			intfName, xnh.Weight, xnh.Flags, xnh.IP(), ScopeTranslate(xnh.Scope), xnh.Pad)
	}
	return
}

func ScopeTranslate(scope uint8) string {
	switch scope {
	case 255:
		return "Nowhere"
	case 254:
		return "Host"
	case 253:
		return "Link"
	case 200:
		return "Site" // Ipv6
	case 0:
		return "Universe"
	default:
		return strconv.Itoa(int(scope))
	}
}

type fdbBridgeMember struct {
	stag      uint16
	pipe_port uint16
}

type fdbBridgeIndex struct {
	bridge int32
	member int32
}

// map TH fdb stag/port to ctag/port on linux bridge
// no need to sanity check reverse intf/ctag map since an intf/ctag only has one upper stag
// ctag=0 will be used for untagged member
var fdbBrmToIndex = map[fdbBridgeMember]fdbBridgeIndex{}

func (m *FdbMain) fdbPortShow(c cli.Commander, w cli.Writer, in *cli.Input) (err error) {
	show_linux := false

	for !in.End() {
		switch {
		case in.Parse("l%*inux"):
			show_linux = true
		default:
			err = cli.ParseError
			return
		}
	}

	vnet.Ports.Foreach(func(ifname string, pe *vnet.PortEntry) {
		if !show_linux || pe.Devtype >= xeth.XETH_DEVTYPE_LINUX_UNKNOWN {
			si, _ := vnet.Ports.GetSiByIndex(pe.Ifindex)
			fmt.Fprintf(w, "si:%v %+v\n", si, pe)
		}
	})

	fmt.Fprintln(w, "\nPortsByIndex")
	lines := 0
	vnet.Ports.ForeachNameByIndex(func(ifindex int32, ifname string) {
		fmt.Fprintf(w, "%10v:%-10v\t", ifindex, ifname)
		lines++
		if lines&7 == 0 {
			fmt.Fprintln(w)
		}
	})
	fmt.Fprintln(w, "\nSiByIfIndex")
	lines = 0
	vnet.Ports.ForeachSiByIndex(func(ifindex int32, si vnet.Si) {
		fmt.Fprintf(w, "%10v:%-10v\t", ifindex, si)
		lines++
		if lines&7 == 0 {
			fmt.Fprintln(w)
		}
	})

	return
}

func (m *FdbMain) cliInit() (err error) {
	v := m.m.v

	cmds := []cli.Command{
		cli.Command{
			Name:      "show ports",
			ShortHelp: "help",
			Action:    m.fdbPortShow,
		},
	}
	for i := range cmds {
		v.CliAdd(&cmds[i])
	}
	return
}

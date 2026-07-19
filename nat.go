package main

import (
	"fmt"
	"os"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// enableIPForwarding turns on kernel IPv4 forwarding. Without it the kernel
// refuses to relay packets between interfaces at all, no matter what
// nftables rules say.
func enableIPForwarding() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("enable ip forwarding: %w", err)
	}
	return nil
}

// ifnameAttr encodes an interface name the way nftables expects it: a fixed
// IFNAMSIZ (16 byte), NUL-terminated buffer.
func ifnameAttr(name string) []byte {
	b := make([]byte, 16)
	copy(b, name+"\x00")
	return b
}

func chainPolicyRef(p nftables.ChainPolicy) *nftables.ChainPolicy {
	return &p
}

// setupNAT makes clients on lanIface (the AP interface) reach the internet
// through wanIface. It's the pure-Go equivalent of mitmrouter's forward/nat
// nftables rules — built directly over netlink via google/nftables instead
// of shelling out to nft:
//
//	chain forward {
//	    type filter hook forward priority filter; policy accept;
//	    ct state related,established accept
//	    iifname $LAN oifname $WAN accept
//	}
//	chain postrouting {
//	    type nat hook postrouting priority srcnat;
//	    oifname $WAN masquerade
//	}
//	chain prerouting {
//	    type nat hook prerouting priority dstnat;
//	    iifname $LAN tcp dport { 80, 443 } redirect to :mitmProxyPort
//	}
func setupNAT(lanIface, wanIface string) error {
	if err := enableIPForwarding(); err != nil {
		return err
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("connect to netfilter: %w", err)
	}

	// Best-effort: remove any "shmitm" table left behind by a previous run
	// of this program within the same boot. Unlike the AP interface's mode,
	// nftables state isn't reset just because our process exited, so a
	// second run would otherwise fail with "table already exists". This has
	// to be its own Flush before the rest: nftables applies a batch
	// atomically, so an expected "no such table" error here would otherwise
	// abort the AddTable/AddChain/AddRule calls below too.
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "shmitm"})
	_ = conn.Flush()

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "shmitm",
	})

	forward := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   chainPolicyRef(nftables.ChainPolicyAccept),
	})

	// ct state established,related accept
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: forward,
		Exprs: []expr.Any{
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// iifname lanIface oifname wanIface accept
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: forward,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameAttr(lanIface)},
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: ifnameAttr(wanIface)},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	postrouting := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	// oifname wanIface masquerade
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: postrouting,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameAttr(wanIface)},
			&expr.Counter{},
			&expr.Masq{},
		},
	})

	prerouting := conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	// iifname lanIface tcp dport {80, 443} redirect to :mitmProxyPort. This
	// transparently rewrites the destination of client-initiated web traffic
	// to a local port, regardless of what the client actually addressed —
	// the client never sees this happen. Whatever's listening on
	// mitmProxyPort becomes a real TCP endpoint for that traffic and has to
	// recover the original destination itself via getsockopt(SO_ORIGINAL_DST).
	for _, port := range []uint16{80, 443} {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: prerouting,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameAttr(lanIface)},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
				&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(mitmProxyPort)},
				&expr.Counter{},
				&expr.Redir{RegisterProtoMin: 1},
			},
		})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("apply nftables ruleset: %w", err)
	}

	go watchNATCounters(table, forward, postrouting, prerouting)

	return nil
}

// watchNATCounters polls the counters on setupNAT's rules and logs whenever
// one changes. It's a live, dependency-free substitute for `nft list
// ruleset` (which needs the nft binary, not necessarily installed) — proof,
// from inside the program itself, of whether traffic is actually reaching
// each rule.
func watchNATCounters(table *nftables.Table, chains ...*nftables.Chain) {
	conn, err := nftables.New()
	if err != nil {
		fmt.Printf("nat: failed to open counter watcher: %v\n", err)
		return
	}

	last := map[string]uint64{}
	for {
		time.Sleep(2 * time.Second)

		for _, chain := range chains {
			rules, err := conn.GetRules(table, chain)
			if err != nil {
				fmt.Printf("nat: failed to read %q counters: %v\n", chain.Name, err)
				continue
			}
			for i, r := range rules {
				for _, e := range r.Exprs {
					c, ok := e.(*expr.Counter)
					if !ok {
						continue
					}
					key := fmt.Sprintf("%s[%d]", chain.Name, i)
					if c.Packets != last[key] {
						last[key] = c.Packets
						fmt.Printf("nat: %s: %d packets, %d bytes\n", key, c.Packets, c.Bytes)
					}
				}
			}
		}
	}
}

package main

import (
	"fmt"
	"os"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
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
			&expr.Masq{},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("apply nftables ruleset: %w", err)
	}
	return nil
}

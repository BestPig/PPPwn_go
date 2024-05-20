package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var if_name string = ""

type guesserType struct {
	string
	gopacket.Packet
}

func GetAPacket(socket *pcap.Handle) gopacket.Packet {
	for {
		// Read in the next packet.
		data, _, err := socket.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			if if_name != "" {
				return nil
			}
			continue
		} else if err != nil {
			log.Printf("[-] Error reading packet: %v", err)
			continue
		}

		return gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
	}
}

func GetPacketWithTypes(socket *pcap.Handle, layerType ...gopacket.LayerType) gopacket.Packet {
	for {
		pkt := GetAPacket(socket)
		found := true
		for _, layerType := range layerType {
			if pkt == nil {
				return nil
			}
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

func WaitPADI(iface string, ch chan guesserType) {
	ihandle, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		fmt.Println("[-] Error creating handle:", err)
	}
	ihandle.SetPromisc(true)
	ihandle.SetTimeout(time.Millisecond * 1000)
	writer, err := ihandle.Activate()
	if err != nil {
		return
	}
	// writer, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
	writer.SetBPFFilter(BPF_FILTER)
	writer.SetDirection(pcap.DirectionIn)

	for if_name == "" {
		pkt := GetPacketWithTypes(writer, layers.LayerTypePPPoETags)
		if pkt == nil {
			continue
		}
		ch <- guesserType{iface, pkt}
		if_name = iface
	}
	writer.Close()
}

func guessRightInterface() (string, gopacket.Packet) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("Error finding devices:", err)
		return "", nil
	}

	fmt.Println("[+] Waiting for PADI...")
	ch := make((chan guesserType), len(devices))
	for _, device := range devices {
		if len(device.Addresses) == 0 {
			continue
		}

		go WaitPADI(device.Name, ch)
	}

	for elem := range ch {
		return if_name, elem
	}
	return "", nil
}

package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func SerializeLayers(layers ...gopacket.Layer) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	serializableLayers := make([]gopacket.SerializableLayer, len(layers))
	for i, layer := range layers {
		serializableLayers[i] = layer.(gopacket.SerializableLayer)
	}

	err := gopacket.SerializeLayers(buffer, opts, serializableLayers...)
	if err != nil {
		return nil, fmt.Errorf("error serializing layers: %v", err)
	}

	return buffer.Bytes(), nil
}

func PpoePacket(srcMac net.HardwareAddr, destMac net.HardwareAddr,
	ethernetType layers.EthernetType, code layers.PPPoECode,
	sessionId uint16,
	tags *layers.PPPoETags) ([]byte, error) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       destMac,
		EthernetType: ethernetType,
	}

	pppoeLayer := &layers.PPPoE{
		Version:   1,
		Type:      1,
		Code:      code,
		SessionId: sessionId,
	}

	return SerializeLayers(ethLayer, pppoeLayer, tags)
}

func PpoeLCP(srcMac net.HardwareAddr, destMac net.HardwareAddr,
	sessionId uint16, code layers.LCPCode, identifier byte) ([]byte, error) {

	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       destMac,
		EthernetType: layers.EthernetTypePPPoESession,
	}

	pppoeLayer := &layers.PPPoE{
		Version:   1,
		Type:      1,
		SessionId: sessionId,
	}

	pppLayer := &layers.PPP{
		PPPType: layers.PPPLinkControlProtocol,
	}

	pppLCP := &layers.PPPLCP{
		Code:       code,
		Identifier: identifier,
		Length:     4, // TODO: fix this
	}

	return SerializeLayers(ethLayer, pppoeLayer, pppLayer, pppLCP)
}

func PpoeIPCP(srcMac net.HardwareAddr, destMac net.HardwareAddr,
	sessionId uint16, code layers.IPCPCode, identifier byte,
	options []layers.IPCPOption) ([]byte, error) {

	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       destMac,
		EthernetType: layers.EthernetTypePPPoESession,
	}

	pppoeLayer := &layers.PPPoE{
		Version:   1,
		Type:      1,
		SessionId: sessionId,
	}

	pppLayer := &layers.PPP{
		PPPType: layers.PPPInternetProtocolControlProtocol,
	}

	pppLCP := &layers.PPPIPCP{
		Code:       code,
		Identifier: identifier,
		Options:    options, // TODO: fix this
	}

	return SerializeLayers(ethLayer, pppoeLayer, pppLayer, pppLCP)
}

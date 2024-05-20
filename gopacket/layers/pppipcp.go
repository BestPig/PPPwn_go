// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
)

type IPCPCode byte

const (
	IPCP_VENDOR_SPECIFIC IPCPCode = iota
	IPCP_CONF_REQUEST    IPCPCode = 1
	IPCP_CONF_ACK        IPCPCode = 2
	IPCP_CONF_NAK        IPCPCode = 3
	IPCP_CONF_REJECT     IPCPCode = 4
	IPCP_TERM_REQUEST    IPCPCode = 5
	IPCP_TERM_ACK        IPCPCode = 6
	IPCP_CODE_REJECT     IPCPCode = 7
	IPCP_PROTOCOL_REJECT IPCPCode = 8
	IPCP_ECHO_REQUEST    IPCPCode = 9
	IPCP_ECHO_REPLY      IPCPCode = 10
	IPCP_DISCARD_REQUEST IPCPCode = 11
	IPCP_RESET_REQUEST   IPCPCode = 14
	IPCP_RESET_ACK       IPCPCode = 15
)

type IPCPOptionType byte

const (
	IPCP_OPT_INVALID                 IPCPOptionType = iota
	IPCP_OPT_IP_ADDRESSES_DEPRECATED IPCPOptionType = 1
	IPCP_OPT_IP_COMPRESSION_PROTOCOL IPCPOptionType = 2
	IPCP_OPT_IP_ADDRESS              IPCPOptionType = 3
	IPCP_OPT_MOBILE_IPV4             IPCPOptionType = 4
	IPCP_OPT_PRIMARY_DNS             IPCPOptionType = 129
	IPCP_OPT_PRIMARY_NBNS            IPCPOptionType = 130
	IPCP_OPT_SECONDARY_DNS           IPCPOptionType = 131
	IPCP_OPT_SECONDARY_NBNS          IPCPOptionType = 132
)

type IPCPOption struct {
	Type   IPCPOptionType
	Length uint8
	Data   []byte
}

// PPPIPCP is the PPPIPCP packet header.
type PPPIPCP struct {
	BaseLayer
	Code       IPCPCode
	Identifier byte
	Length     uint16
	Options    []IPCPOption
}

func NewIPAddressOption(ip net.IP) IPCPOption {
	return IPCPOption{
		Type:   IPCP_OPT_IP_ADDRESS,
		Length: 4,
		Data:   ip.To4(),
	}
}

// LayerType returns gopacket.LayerLCP.
func (m *PPPIPCP) LayerType() gopacket.LayerType { return LayerTypePPPIPCP }

func decodePPPIPCP(data []byte, p gopacket.PacketBuilder) error {
	ipcp := &PPPIPCP{
		Code:       IPCPCode(data[0]),
		Identifier: data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
		BaseLayer:  BaseLayer{Contents: data},
	}
	for offset := 4; offset < len(data); {
		optType := IPCPOptionType(data[offset])
		optLength := data[offset+1] - 2
		optData := data[offset+2 : offset+2+int(optLength)]
		ipcp.Options = append(ipcp.Options, IPCPOption{
			Type:   optType,
			Length: optLength,
			Data:   optData,
		})
		offset += 2 + int(optLength)
	}

	p.AddLayer(ipcp)
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (m *PPPIPCP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var size uint8 = 4
	for _, opt := range m.Options {
		size += 2 + opt.Length
	}
	bytes, err := b.PrependBytes(int(size))
	if err != nil {
		return err
	}

	bytes[0] = byte(m.Code)
	bytes[1] = m.Identifier
	binary.BigEndian.PutUint16(bytes[2:4], uint16(size))

	offset := 4
	if m.Options != nil {
		for _, opt := range m.Options {
			bytes[offset] = uint8(opt.Type)
			bytes[offset+1] = 2 + opt.Length
			copy(bytes[offset+2:], opt.Data)
			offset += 2 + len(opt.Data)
		}
	}

	return nil
}

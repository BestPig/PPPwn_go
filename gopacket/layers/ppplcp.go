// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"

	"github.com/google/gopacket"
)

type LCPCode byte

const (
	LCP_CODE_INVALID    LCPCode = iota
	LCP_CONF_REQUEST    LCPCode = 1
	LCP_CONF_ACK        LCPCode = 2
	LCP_CONF_NACK       LCPCode = 3
	LCP_CONF_REJECT     LCPCode = 4
	LCP_TERM_REQUEST    LCPCode = 5
	LCP_TERM_ACK        LCPCode = 6
	LCP_CODE_REJECT     LCPCode = 7
	LCP_PROTO_REJECT    LCPCode = 8
	LCP_ECHO_REQUEST    LCPCode = 9
	LCO_ECHO_REPLY      LCPCode = 10
	LCP_DISCARD_REQUEST LCPCode = 11
)

type PPPLCPOption struct {
	Type byte
	Data []byte
}

// PPPLCP is the PPPLCP packet header.
type PPPLCP struct {
	BaseLayer
	Code          LCPCode
	Identifier    byte
	Length        uint16
	MagicNumber   uint32
	PPPLCPOptions []PPPLCPOption
}

// LayerType returns gopacket.LayerLCP.
func (m *PPPLCP) LayerType() gopacket.LayerType { return LayerTypeLCP }

func decodeLCP(data []byte, p gopacket.PacketBuilder) error {
	var code byte = data[0]
	var identifier byte = data[1]

	lcp := &PPPLCP{
		Code:       LCPCode(code),
		Identifier: identifier,
		Length:     binary.BigEndian.Uint16(data[2:4]),
		BaseLayer:  BaseLayer{Contents: data},
	}

	if code == 9 || code == 10 {
		lcp.MagicNumber = binary.BigEndian.Uint32(data[4:8])
	}
	p.AddLayer(lcp)
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (m *PPPLCP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	size := 4
	if m.Code == 9 || m.Code == 10 {
		size += 4
	}
	bytes, err := b.PrependBytes(size)
	if err != nil {
		return err
	}
	bytes[0] = byte(m.Code)
	bytes[1] = m.Identifier

	binary.BigEndian.PutUint16(bytes[2:4], m.Length)
	if m.Code == 9 || m.Code == 10 {
		binary.BigEndian.PutUint32(bytes[4:8], m.MagicNumber)
	}

	for _, option := range m.PPPLCPOptions {
		bytes, err = b.AppendBytes(len(option.Data) + 2)
		if err != nil {
			return err
		}
		bytes[0] = option.Type
		bytes[1] = 2 + byte(len(option.Data))
		copy(bytes[2:], option.Data)
	}

	return nil
}

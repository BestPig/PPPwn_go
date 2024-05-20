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

type PPPoETagName uint16

const (
	PPPOETAG_INVALID             PPPoETagName = iota
	PPPoETag_ENDOFLIST           PPPoETagName = 0x0000
	PPPOETAG_SERVICENAME         PPPoETagName = 0x0101
	PPPOETAG_ACNAME              PPPoETagName = 0x0102
	PPPOETAG_HOSTUNIQ            PPPoETagName = 0x0103
	PPPOETAG_ACCOOKIE            PPPoETagName = 0x0104
	PPPOETAG_VENDOR_SPECIFIC     PPPoETagName = 0x0105
	PPPOETAG_CREDITS             PPPoETagName = 0x0106
	PPPOETAG_METRICS             PPPoETagName = 0x0107
	PPPOETAG_SEQUENCE_NUMBER     PPPoETagName = 0x0108
	PPPOETAG_CREDIT_SCALE_FACTOR PPPoETagName = 0x0109
	PPPOETAG_RELAY_SESSION_ID    PPPoETagName = 0x0110
	PPPOETAG_PPP_MAX_PAYLOAD     PPPoETagName = 0x0120
	PPPOETAG_SERVICE_NAME_ERROR  PPPoETagName = 0x0201
	PPPOETAG_ACSYSTEM_ERROR      PPPoETagName = 0x0202
	PPPOETAG_GENERIC_ERROR       PPPoETagName = 0x0203
)

type PPPoETag struct {
	Type   PPPoETagName
	Length uint16
	Value  []byte
}

// PPPoE is the layer for PPPoE encapsulation headers.
type PPPoETags struct {
	BaseLayer
	Tags []PPPoETag
}

// LayerType returns gopacket.LayerTypePPPoE.
func (p *PPPoETags) LayerType() gopacket.LayerType {
	return LayerTypePPPoETags
}

func (p *PPPoETags) GetPPPoETagValue(tag PPPoETagName) []byte {
	for _, t := range p.Tags {
		if t.Type == tag {
			return t.Value
		}
	}
	return nil
}

// decodePPPoE decodes the PPPoE header (see http://tools.ietf.org/html/rfc2516).
func decodePPPoETags(data []byte, p gopacket.PacketBuilder) error {
	pppoe_tags := &PPPoETags{
		BaseLayer: BaseLayer{Contents: data},
	}
	tags := []PPPoETag{}
	for len(data) > 0 {
		tag := PPPoETag{
			Type:   PPPoETagName(binary.BigEndian.Uint16(data[0:2])),
			Length: binary.BigEndian.Uint16(data[2:4]),
			Value:  data[4 : 4+binary.BigEndian.Uint16(data[2:4])],
		}
		data = data[4+tag.Length:]
		tags = append(tags, tag)
	}
	pppoe_tags.Tags = tags
	p.AddLayer(pppoe_tags)
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (p *PPPoETags) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	for _, tag := range p.Tags {
		bytes, err := b.PrependBytes(4 + len(tag.Value))
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes[0:2], uint16(tag.Type))
		binary.BigEndian.PutUint16(bytes[2:4], uint16(len(tag.Value)))
		copy(bytes[4:], tag.Value)
	}
	return nil
}

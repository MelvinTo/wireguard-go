package device

import (
	"encoding/binary"
	"net/netip"
	"time"
)

const (
	icmpv4ProtocolNumber = 1
	icmpv4Echo           = 8
	icmpv4Reply           = 0
	icmpv4ChecksumOffset = 2
	icmpv4SeqOffset = 6
	icmpv4Size           = 8
	ipv4Size             = 20
	ipv4TotalLenOffset   = 2
	ipv4ChecksumOffset   = 10
	ttl                  = 65
	headerSize           = ipv4Size + icmpv4Size
	payloadSize          = 32
	totalSize		     = headerSize + payloadSize
)

func (peer *Peer) SendPing() {
	src := peer.device.ping.src
	dst := peer.ping.target

	if !src.IsValid() || !dst.IsValid() {
		return // do nothing if ping is not well configured
	}

	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		elem := peer.device.NewOutboundElement()

		peer.ping.lastPingSeq.Add(1)
		seq := uint16(peer.ping.lastPingSeq.Load())
		pkt := peer.PreparePingPacket(src, seq)

		copy(elem.buffer[MessageTransportHeaderSize:], pkt)
		elem.packet = elem.buffer[MessageTransportHeaderSize:MessageTransportHeaderSize+len(pkt)]

		elemsContainer := peer.device.GetOutboundElementsContainer()
		elemsContainer.elems = append(elemsContainer.elems, elem)

		peer.ping.lastSentPingNano.Store(time.Now().UnixNano())

		select {
		case peer.queue.staged <- elemsContainer:
			peer.device.log.Errorf("%v - Sending ping packet from %v to %v", peer, src, dst)
		default:
			peer.device.PutMessageBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
		}
	}
	peer.SendStagedPackets()
}

func testEq(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

func (peer *Peer) CheckPing(icmpPacket []byte) {
	if len(icmpPacket) != totalSize {
		return
	}

	// must be a reply packet
	if icmpPacket[ipv4Size] != icmpv4Reply ||
		icmpPacket[ipv4Size+1] != 0 {
		return
	}

	// reply seq should match request seq
	seq := binary.BigEndian.Uint16(icmpPacket[ipv4Size+icmpv4SeqOffset:])
	if seq != uint16(peer.ping.lastPingSeq.Load()) {
		return
	}

	// src ip should match the ping target
	if !testEq(icmpPacket[12:16], peer.ping.target.AsSlice()) {
		return
	}

	// dst ip should match the ping source
	if !testEq(icmpPacket[16:20], peer.device.ping.src.AsSlice()) {
		return
	}

	// public key should match the payload
	publicKey := [32]byte(peer.handshake.remoteStatic)
	payload := icmpPacket[headerSize:]

	if !testEq(payload[:], publicKey[:]) {
		peer.device.log.Errorf("%v - unmatched payload\n%x\n%x", peer, payload, publicKey)
		return
	}


	now := time.Now().UnixNano()
	latency := uint64(now - peer.ping.lastSentPingNano.Load())
	peer.ping.latency.Store(latency)

	peer.device.log.Errorf("%v - Got an admin ping packet, latency %0.2v ms", peer, float64(latency)/1000000)

	// seq should be the same as peer seq
	// icmpPacket

	//publicKey := [32]byte(peer.handshake.remoteStatic)
	//return publicKey == binary.BigEndian.Uint32(icmpPacket[:4])
}

func (peer *Peer) PreparePingPacket(src netip.Addr, seq uint16) []byte {
	payload := make([]byte, 32)
	publicKey := [32]byte(peer.handshake.remoteStatic)
	copy(payload[:], publicKey[:])

	return genICMPv4(payload, peer.ping.target, src, seq)
}

// Checksum is the "internet checksum" from https://tools.ietf.org/html/rfc1071.
func checksum(buf []byte, initial uint16) uint16 {
	v := uint32(initial)
	for i := 0; i < len(buf)-1; i += 2 {
		v += uint32(binary.BigEndian.Uint16(buf[i:]))
	}
	if len(buf)%2 == 1 {
		v += uint32(buf[len(buf)-1]) << 8
	}
	for v > 0xffff {
		v = (v >> 16) + (v & 0xffff)
	}
	return ^uint16(v)
}

func genICMPv4(payload []byte, dst, src netip.Addr, seq uint16) []byte {

	pkt := make([]byte, headerSize+len(payload))

	ip := pkt[0:ipv4Size]
	icmpv4 := pkt[ipv4Size : ipv4Size+icmpv4Size]

	// https://tools.ietf.org/html/rfc792
	icmpv4[0] = icmpv4Echo // type
	icmpv4[1] = 0          // code

	binary.BigEndian.PutUint16(icmpv4[icmpv4SeqOffset:], seq)

	copy(pkt[headerSize:], payload)

	// checksum of icmpv4 header and payload
	icmpPkt := pkt[ipv4Size:]
	chksum := checksum(icmpPkt, 0)
	binary.BigEndian.PutUint16(icmpv4[icmpv4ChecksumOffset:], chksum)

	// prepare ipv4 header
	// https://tools.ietf.org/html/rfc760 section 3.1
	length := uint16(len(pkt))
	ip[0] = (4 << 4) | (ipv4Size / 4)
	binary.BigEndian.PutUint16(ip[ipv4TotalLenOffset:], length)
	ip[8] = ttl
	ip[9] = icmpv4ProtocolNumber
	copy(ip[12:], src.AsSlice())
	copy(ip[16:], dst.AsSlice())

	// checksum of ipv4 header
	chksum = checksum(ip[:], 0)
	binary.BigEndian.PutUint16(ip[ipv4ChecksumOffset:], chksum)

	return pkt
}

package device

import (
	"encoding/json"
	"encoding/binary"
	"encoding/base64"
	"net/netip"
)

const (
	udpProtocolNumber = 17
	udpHeaderSize           = 8
	udpTotalHeaderSize = ipv4Size + udpHeaderSize
)

type PeerRequest struct {
	Type string `json:"type"`
	From string `json:"from"`
}

type PeerResponse struct {
	Type string `json:"type"`
	From string `json:"from"`
	Name string `json:"name,omitempty"`
	Model string `json:"model,omitempty"`
}

func (peer *Peer) prepareRequestInfoPacket(dst, src netip.Addr) []byte {
	payload := peer.prepareRequestInfoPayload()
	pkt := peer.newUDPHeader(dst, src, len(payload))
	copy(pkt[udpTotalHeaderSize:], payload)
	return pkt
}

func (peer *Peer) prepareRequestInfoPayload() []byte {
	base64Key := base64.StdEncoding.EncodeToString(peer.device.staticIdentity.publicKey[:])
	req := PeerRequest{ Type: "msg:info_request", From: base64Key }
	data, _ := json.Marshal(req)
	peer.device.log.Errorf("Req: %v", string(data))
	return data
}

func (peer *Peer) newUDPHeader(dst, src netip.Addr, payloadLength int) []byte {
	pkt := make([]byte, udpTotalHeaderSize + payloadLength)

	ip := pkt[0:ipv4Size]
	udp := pkt[ipv4Size : udpTotalHeaderSize]

	binary.BigEndian.PutUint16(udp, 0) // src port (use 0 as placeholder, optional)
	binary.BigEndian.PutUint16(udp[2:], 6666) // dst port
	binary.BigEndian.PutUint16(udp[4:], uint16(8 + payloadLength)) // length
	binary.BigEndian.PutUint16(udp[6:], 0) // checksum (all zeros, optional)

	// prepare ipv4 header
	// https://tools.ietf.org/html/rfc760 section 3.1
	length := uint16(len(pkt))
	ip[0] = (4 << 4) | (ipv4Size / 4)
	binary.BigEndian.PutUint16(ip[ipv4TotalLenOffset:], length)
	ip[8] = ttl
	ip[9] = udpProtocolNumber
	copy(ip[12:], src.AsSlice())
	copy(ip[16:], dst.AsSlice())

	// checksum of ipv4 header
	chksum := checksum(ip[:], 0)
	binary.BigEndian.PutUint16(ip[ipv4ChecksumOffset:], chksum)

	return pkt
}

func (peer *Peer) SendInfoRequest() {
	src := peer.device.addr
	dst := peer.addr

	if !src.IsValid() || !dst.IsValid() {
		return // do nothing if ping is not well configured
	}

	if peer.lastHandshakeNano.Load() == 0 {
		return // do nothing if handshake is not done
	}

	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		elem := peer.device.NewOutboundElement()

		pkt := peer.prepareRequestInfoPacket(dst, src)

		copy(elem.buffer[MessageTransportHeaderSize:], pkt)
		elem.packet = elem.buffer[MessageTransportHeaderSize:MessageTransportHeaderSize+len(pkt)]

		elemsContainer := peer.device.GetOutboundElementsContainer()
		elemsContainer.elems = append(elemsContainer.elems, elem)

		select {
		case peer.queue.staged <- elemsContainer:
			peer.device.log.Verbosef("%v - Sending info req packet from %v to %v", peer, src, dst)
		default:
			peer.device.PutMessageBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
		}
	}
	peer.SendStagedPackets()
}

func (peer *Peer) HandleControlResponse(pkt []byte) bool {
	if len(pkt) < udpTotalHeaderSize {
		return false
	}

	udp := pkt[ipv4Size : udpTotalHeaderSize]

	destPort := binary.BigEndian.Uint16(udp[2:])

	if destPort != 6666 {
		return false
	}

	pktLen := binary.BigEndian.Uint16(udp[4:])
	if len(pkt) != ipv4Size + int(pktLen) {
		peer.device.log.Errorf("%v - unmatched packet length, length in udp header should equal to the actual length", peer)
		return false
	}

	payload := pkt[udpTotalHeaderSize:]

	var resp PeerResponse
	err := json.Unmarshal(payload, &resp)
	if err != nil {
		peer.device.log.Errorf("%v - failed to unmarshal peer response: %v", peer, err)
		return false
	}

	if resp.Type != "msg:info_response" {
		peer.device.log.Errorf("%v - unmatched peer response type, expected msg:info_response, got %v", peer, resp.Type)
		return false
	}

	return peer.handleInfoResponse(resp)
}

func (peer *Peer) handleInfoResponse(resp PeerResponse) bool {
	peer.device.log.Verbosef("%v - Got an info response: %v", peer, resp)
	peer.name = resp.Name
	peer.model = resp.Model

	return true
}

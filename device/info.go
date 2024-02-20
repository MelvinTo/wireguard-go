package device

import (
	"encoding/json"
	"encoding/binary"
	"encoding/hex"
	"encoding/base64"
	"net/netip"
	"time"
	"fmt"
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

type PeerInfoRequest struct {
	Type string `json:"type"`
	From string `json:"from"`
	Key string `json:"key"`
}

type PeerGenericResponse struct {
	Type string `json:"type"`
	From string `json:"from"`
}

type PeerInfoResponse struct {
	Type string `json:"type"`
	From string `json:"from"`
	Name string `json:"name,omitempty"`
	Model string `json:"model,omitempty"`
}

//{"peerIP":"10.49.211.52/32","allowedIPs":["10.49.211.52/32"],"endpoint":"192.168.203.65:49691","type":"msg:peer_info_response","from":"n+umBCFw3kLurM3gKL9WGe55i1Oh7pODroGshYRQ/m0="}
//
//{"origEndpoint":"d61qb2k4e.dd.firewalla.org:51821","peerIP":"10.49.211.45/32","allowedIPs":["10.11.160.0/24","10.49.211.45/32","192.168.1.0/24","192.168.10.0/24","192.168.203.0/24","192.168.205.0/24","192.168.7.0/24","192.168.77.0/24","192.168.85.0/24"],"v4":"124.78.134.120","ts4":1708341654,"port4":51821,"endpoint":"192.168.203.1:51821","type":"msg:peer_info_response","from":"n+umBCFw3kLurM3gKL9WGe55i1Oh7pODroGshYRQ/m0="}
//

type PeerExtendedInfoResponse struct {
	Type string `json:"type"`
	From string `json:"from"`
	Key string `json:"key"`
	PeerIP string `json:"peerIP,omitempty"`
	AllowedIPs []string `json:"allowedIPs,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	OrigEndpoint string `json:"origEndpoint,omitempty"`
}

func (resp *PeerExtendedInfoResponse) IsValid() bool {
	if resp.Key == "" {
		return false
	}

	if resp.Endpoint == "" {
		return false
	}

	if resp.PeerIP == "" {
		return false
	}

	return true
}

type EndpointInfo struct {
	V4 string `json:"v4,omitempty"`
	V6 string `json:"v6,omitempty"`
	V4Timestamp uint64 `json:"ts4,omitempty"`
	V6Timestamp uint64 `json:"ts6,omitempty"`
	Port uint16 `json:"port"`
}

// v4 only
func (info *EndpointInfo) IsValid() bool {
	now := uint64(time.Now().Unix())
	if info.V4 != "" &&
		info.Port != 0 &&
		now - info.V4Timestamp < 300 {
		return true
	}

	if info.V6 != "" &&
		info.Port != 0 &&
		now - info.V6Timestamp < 300 {
		return true
	}

	return false
}

func (info *EndpointInfo) GetEndpointV4Addr() string {
	if info.V4 != "" &&
		info.Port != 0 {
		fmt.Sprintf("%v:%v", info.V4, info.Port)
	}

	return ""
}

func (info *EndpointInfo) String() string {
	return fmt.Sprintf("EndpointInfo{V4: %v, V6: %v, Port: %v, V4Timestamp: %v, V6Timestamp: %v}", info.V4, info.V6, info.Port, info.V4Timestamp, info.V6Timestamp)
}

type PeerEndpointInfo struct {
	Type string `json:"type"`
	From string `json:"from"`
    AsRouter bool `json:"asRouter"`
	Peers map[string]EndpointInfo `json:"peers"`
}

func (peer *Peer) prepareRequestInfoPacket(dst, src netip.Addr) []byte {
	payload := peer.prepareRequestInfoPayload()
	pkt := peer.newUDPHeader(dst, src, len(payload))
	copy(pkt[udpTotalHeaderSize:], payload)
	return pkt
}

func (peer *Peer) prepareRequestExtendedInfoPacket(dst, src netip.Addr, key string) []byte {
	payload := peer.prepareRequestExtendedInfoPayload(key)
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

func (peer *Peer) prepareRequestExtendedInfoPayload(key string) []byte {
	base64Key := base64.StdEncoding.EncodeToString(peer.device.staticIdentity.publicKey[:])
	req := PeerInfoRequest{ Type: "msg:peer_info_request", From: base64Key, Key: key }
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

func (peer *Peer) SendExtendedInfoRequest(key string) {
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

		pkt := peer.prepareRequestExtendedInfoPacket(dst, src, key)

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

	var resp PeerGenericResponse
	err := json.Unmarshal(payload, &resp)
	if err != nil {
		peer.device.log.Errorf("%v - failed to unmarshal peer response: %v", peer, err)
		return false
	}

	switch resp.Type {
	case "msg:info_response":
		return peer.handleInfoResponse(payload)
	case "msg:peer_info_response":
		return peer.handlePeerInfoResponse(payload)
	case "msg:peer_endpoint_info":
		return peer.handleEndpointInfo(payload)
	default:
		peer.device.log.Errorf("%v - unmatched peer response type, expected msg:info_response, got %v", peer, resp.Type)
		return false
	}
}

func (peer *Peer) handleInfoResponse(payload []byte) bool {
	var resp PeerInfoResponse
	err := json.Unmarshal(payload, &resp)
	if err != nil {
		peer.device.log.Errorf("%v - failed to unmarshal peer info response: %v", peer, err)
		return false
	}

	peer.device.log.Verbosef("%v - Got an info response: %v", peer, resp)
	peer.name = resp.Name
	peer.model = resp.Model

	return true
}


func (peer *Peer) handlePeerInfoResponse(payload []byte) bool {
	var resp PeerExtendedInfoResponse
	err := json.Unmarshal(payload, &resp)
	if err != nil {
		peer.device.log.Errorf("%v - failed to unmarshal peer extended info response: %v", peer, err)
		return false
	}

	if !resp.IsValid() {
		peer.device.log.Errorf("Invalid peer info response: %v", resp)
		return false
	}

	peer.device.log.Verbosef("%v - Got an extended info response: %v", peer, resp)

	hexBytes, err := base64.StdEncoding.DecodeString(resp.Key)
	if err != nil {
		peer.device.log.Errorf("Failed to decode base64 public key: %v, err: %v", resp.Key, err)
		return false
	}

	hexString := hex.EncodeToString(hexBytes)

	var publicKey NoisePublicKey
	err = publicKey.FromHex(hexString)
	if err != nil {
		peer.device.log.Errorf("Failed to decode hex public key: %v, err: %v", resp.Key, err)
		return false
	}

	dummy := false
	// Ignore peer with the same public key as this device.
	peer.device.staticIdentity.RLock()
	dummy = peer.device.staticIdentity.publicKey.Equals(publicKey)
	peer.device.staticIdentity.RUnlock()

	if dummy {
		return false
	}

	p := peer.device.LookupPeer(publicKey)
	if p != nil { // no need to do anything if key already exists
		return true
	}

	peer.createPeerFromInfoResponse(resp)

	return true
}

func (peer *Peer) createPeerFromInfoResponse(resp PeerExtendedInfoResponse) {
	hexBytes, err := base64.StdEncoding.DecodeString(resp.Key)
	if err != nil {
		peer.device.log.Errorf("Failed to decode base64 public key: %v, err: %v", resp.Key, err)
		return
	}

	hexString := hex.EncodeToString(hexBytes)

	var publicKey NoisePublicKey
	err = publicKey.FromHex(hexString)
	if err != nil {
		peer.device.log.Errorf("Failed to decode hex public key: %v, err: %v", resp.Key, err)
		return
	}

	prefix, err := netip.ParsePrefix(resp.PeerIP)
	if err != nil {
		peer.device.log.Errorf("UAPI: Failed to parse peer ip: %v, err: %v", resp.PeerIP, err)
		return
	}

	addr := prefix.Addr()

	p, err := peer.device.NewPeer(publicKey)
	p.isDiscovered.Store(true)
	p.addr = addr

	peer.device.log.Verbosef("%v - UAPI: Created", p)

	// endpoint
	if resp.Endpoint != "" {
		peer.device.log.Verbosef("%v - UAPI: Updating endpoint", p)
		endpoint, err := peer.device.net.bind.ParseEndpoint(resp.Endpoint)
		if err != nil {
			peer.device.log.Errorf("UAPI: Failed to parse endpoint: %v, err: %v", resp.Endpoint, err)
		} else {
			p.endpoint.Lock()
			defer p.endpoint.Unlock()
			p.endpoint.val = endpoint
			p.endpoint.lastEndpointSetNano.Store(time.Now().UnixNano())
		}
	}

	// original endpoint
	if resp.OrigEndpoint != "" {
		peer.device.log.Verbosef("%v - UAPI: Updating original endpoint", p)
		p.history.originalEndpoint = resp.OrigEndpoint
	}

	// keepalive
	p.persistentKeepaliveInterval.Swap(uint32(17))

	// allowedips
	for _, allowedIP := range resp.AllowedIPs {
		if allowedIP == "0.0.0.0/0" {
			continue
		}

		prefix, err := netip.ParsePrefix(allowedIP)
		if err != nil {
			peer.device.log.Errorf("UAPI: Failed to parse allowed ip: %v, err: %v", resp.PeerIP, err)
		} else {
			peer.device.allowedips.Insert(prefix, p)
		}
	}

	if peer.device.isUp() {
		peer.device.log.Verbosef("%v - UAPI: Starting Peer", p)
		p.Start()
		// p.SendKeepalive()
		p.SendStagedPackets()
	}

	return
}

func (peer *Peer) SetEndpointFromEndpointInfo(endpointInfo *EndpointInfo) {
	peer.device.log.Verbosef("%v - Info: Updating endpoint from info %v", peer, endpointInfo)
	addr := endpointInfo.GetEndpointV4Addr()
	if addr != "" {
		endpoint, err := peer.device.net.bind.ParseEndpoint(addr)
		if err != nil {
			peer.device.log.Errorf("Info: Failed to parse endpoint: %v, err: %v", addr, err)
			return
		}
		peer.endpoint.Lock()
		defer peer.endpoint.Unlock()
		peer.endpoint.val = endpoint
		peer.endpoint.lastEndpointSetNano.Store(time.Now().UnixNano())
	}
}

func (peer *Peer) handleEndpointInfo(payload []byte) bool {
	peer.device.log.Verbosef("Raw endpoint info: %v", string(payload))

	var resp PeerEndpointInfo
	err := json.Unmarshal(payload, &resp)
	if err != nil {
		peer.device.log.Errorf("%v - failed to unmarshal peer endpoint response: %v", peer, err)
		return false
	}

	peer.device.log.Verbosef("%v - Got an endpoint info response: %v", peer, resp)

	for k, v := range resp.Peers {
		peer.device.log.Verbosef("%v - Peer: %v, Endpoint: %v", peer, k, v)

		if !v.IsValid() {
			peer.device.log.Verbosef("Invalid peer endpoint info: %v for peer %v", v, k)
			continue
		}

		hexBytes, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			peer.device.log.Errorf("Failed to decode base64 public key: %v, err: %v", k, err)
			continue
		}

		hexString := hex.EncodeToString(hexBytes)

		var publicKey NoisePublicKey
		err = publicKey.FromHex(hexString)
		if err != nil {
			peer.device.log.Errorf("Failed to decode hex public key: %v, err: %v", k, err)
			continue
		}

		p := peer.device.LookupPeer(publicKey)
		if p == nil {
			// in the future, need to auto discover new peers
			peer.device.log.Verbosef("Peer not found: %v, going to send discover message", k)
			peer.SendExtendedInfoRequest(k)
			continue
		}

		lastSuccessfulPong := p.ping.lastSuccessfulPongNano.Load()
		now := time.Now().UnixNano()
		// if the last successful pong is more than 30 seconds ago, update endpoint info
		if now - lastSuccessfulPong > 30 * 1000000000 {
			p.SetEndpointFromEndpointInfo(&v)
		}
	}

	return true
}

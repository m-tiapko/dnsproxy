package proxy

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// udpCreate - create a UDP listening socket
func (p *Proxy) udpCreate() error {
	log.Printf("Creating the UDP server socket")
	udpAddr := p.UDPListenAddr
	udpListen, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return errorx.Decorate(err, "couldn't listen to UDP socket")
	}

	err = udpSetOptions(udpListen)
	if err != nil {
		udpListen.Close()
		return fmt.Errorf("udpSetOptions: %s", err)
	}

	p.udpListen = udpListen
	log.Printf("Listening to udp://%s", p.udpListen.LocalAddr())
	return nil
}

// udpPacketLoop listens for incoming UDP packets
func (p *Proxy) udpPacketLoop(conn *net.UDPConn) {
	log.Printf("Entering the UDP listener loop on %s", conn.LocalAddr())
	b := make([]byte, dns.MaxMsgSize)
	for {
		p.RLock()
		if !p.started {
			return
		}
		p.RUnlock()

		n, localIP, remoteAddr, err := p.readUDP(conn, b)
		// documentation says to handle the packet even if err occurs, so do that first
		if n > 0 {
			// make a copy of all bytes because ReadFrom() will overwrite contents of b on next call
			// we need the contents to survive the call because we're handling them in goroutine
			packet := make([]byte, n)
			copy(packet, b)
			p.guardMaxGoroutines()
			go func() {
				p.handleUDPPacket(packet, localIP, remoteAddr, conn)
				p.freeMaxGoroutines()
			}()
		}
		if err != nil {
			if isConnClosed(err) {
				log.Printf("udpListen.ReadFrom() returned because we're reading from a closed connection, exiting loop")
				break
			}
			log.Printf("got error when reading from UDP listen: %s", err)
		}
	}
}

// handleUDPPacket processes the incoming UDP packet and sends a DNS response
func (p *Proxy) handleUDPPacket(packet []byte, localIP net.IP, remoteAddr *net.UDPAddr, conn *net.UDPConn) {
	log.Tracef("Start handling new UDP packet from %s", remoteAddr)

	msg := &dns.Msg{}
	err := msg.Unpack(packet)
	if err != nil {
		log.Printf("error handling UDP packet: %s", err)
		return
	}

	d := &DNSContext{
		Proto:   ProtoUDP,
		Req:     msg,
		Addr:    remoteAddr,
		Conn:    conn,
		localIP: localIP,
	}

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
	}
}

// Writes a response to the UDP client
func (p *Proxy) respondUDP(d *DNSContext) error {
	resp := d.Res
	conn := d.Conn.(*net.UDPConn)

	bytes, err := resp.Pack()
	if err != nil {
		return errorx.Decorate(err, "couldn't convert message into wire format: %s", resp.String())
	}

	rAddr := d.Addr.(*net.UDPAddr)
	n, _, err := conn.WriteMsgUDP(bytes, udpMakeOOBWithSrc(d.localIP), rAddr)
	if n == 0 && isConnClosed(err) {
		return err
	}
	if err != nil {
		return errorx.Decorate(err, "conn.WriteMsgUDP() returned error")
	}
	if n != len(bytes) {
		return fmt.Errorf("conn.WriteTo() returned with %d != %d", n, len(bytes))
	}
	return nil
}

// udpGetOOBSize - get max. size of received OOB data
func udpGetOOBSize() int {
	oob4 := ipv4.NewControlMessage(ipv4.FlagDst | ipv4.FlagInterface)
	oob6 := ipv6.NewControlMessage(ipv6.FlagDst | ipv6.FlagInterface)

	if len(oob4) > len(oob6) {
		return len(oob4)
	}
	return len(oob6)
}

// udpSetOptions - set options on a UDP socket to be able to receive the necessary OOB data
func udpSetOptions(c *net.UDPConn) error {
	err6 := ipv6.NewPacketConn(c).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(c).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err6 != nil && err4 != nil {
		return errorx.DecorateMany("SetControlMessage: ", err4, err6)
	}
	return nil
}

// udpMakeOOBWithSrc - make OOB data with a specified source IP
func udpMakeOOBWithSrc(ip net.IP) []byte {
	if ip.To4() == nil {
		cm := &ipv6.ControlMessage{}
		cm.Src = ip
		return cm.Marshal()
	}

	cm := &ipv4.ControlMessage{}
	cm.Src = ip
	return cm.Marshal()
}

// readUDP - receive payload and OOB data from UDP socket
func (p *Proxy) readUDP(c *net.UDPConn, buf []byte) (n int, localIP net.IP, remoteAddr *net.UDPAddr, err error) {
	var oobn int
	oob := make([]byte, p.udpOOBSize)
	n, oobn, _, remoteAddr, err = c.ReadMsgUDP(buf, oob)
	if err != nil {
		return -1, nil, nil, err
	}

	localIP = udpGetDstFromOOB(oob[:oobn])
	return n, localIP, remoteAddr, nil
}

// udpGetDstFromOOB - get destination IP from OOB data
func udpGetDstFromOOB(oob []byte) net.IP {
	cm6 := &ipv6.ControlMessage{}
	if cm6.Parse(oob) == nil && cm6.Dst != nil {
		return cm6.Dst
	}

	cm4 := &ipv4.ControlMessage{}
	if cm4.Parse(oob) == nil && cm4.Dst != nil {
		return cm4.Dst
	}

	return nil
}

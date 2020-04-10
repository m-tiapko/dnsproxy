package proxy

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
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

	bytes, err := resp.Pack()
	if err != nil {
		return errorx.Decorate(err, "couldn't convert message into wire format: %s", resp.String())
	}

	n, err := udpWrite(bytes, d)
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

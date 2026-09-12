// identity-lab generates controlled local traffic and an independent truth
// manifest. Run it while ohmyosi is capturing with -research-trace.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"ohmyosi/internal/researchtrace"
)

func main() {
	out := flag.String("out", "", "write independent truth NDJSON here")
	ipText := flag.String("ip", "127.0.0.1", "loopback address shared by every controlled destination")
	basePort := flag.Int("base-port", 18080, "HTTP port; TLS and UDP use the next two ports")
	dnsPort := flag.Int("dns-port", 53, "controlled DNS UDP port (use 53 for ohmyosi DNS decoding)")
	hold := flag.Duration("hold", time.Second, "keep flows open after generation so capture can observe them")
	flag.Parse()
	if *out == "" {
		fatal(errors.New("-out is required"))
	}
	ip, err := netip.ParseAddr(*ipText)
	if err != nil || !ip.IsLoopback() || !ip.Is4() {
		fatal(fmt.Errorf("-ip must be an IPv4 loopback address: %q", *ipText))
	}
	if *basePort < 1024 || *basePort > 65533 {
		fatal(errors.New("-base-port must be between 1024 and 65533"))
	}
	if *dnsPort < 1 || *dnsPort > 65535 {
		fatal(errors.New("-dns-port must be between 1 and 65535"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cert, err := certificate()
	if err != nil {
		fatal(err)
	}
	httpAddr := net.JoinHostPort(ip.String(), fmt.Sprint(*basePort))
	tlsAddr := net.JoinHostPort(ip.String(), fmt.Sprint(*basePort+1))
	udpAddr := net.JoinHostPort(ip.String(), fmt.Sprint(*basePort+2))
	dnsAddr := net.JoinHostPort(ip.String(), fmt.Sprint(*dnsPort))

	httpListener, err := net.Listen("tcp4", httpAddr)
	if err != nil {
		fatal(err)
	}
	defer httpListener.Close()
	tlsListener, err := tls.Listen("tcp4", tlsAddr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		fatal(err)
	}
	defer tlsListener.Close()
	udpServer, err := net.ListenPacket("udp4", udpAddr)
	if err != nil {
		fatal(err)
	}
	defer udpServer.Close()
	dnsServer, err := net.ListenPacket("udp4", dnsAddr)
	if err != nil {
		fatal(fmt.Errorf("start controlled DNS on %s: %w", dnsAddr, err))
	}
	defer dnsServer.Close()

	var servers sync.WaitGroup
	serveTCP(ctx, &servers, httpListener)
	serveTCP(ctx, &servers, tlsListener)
	serveUDP(ctx, &servers, udpServer)
	serveDNS(ctx, &servers, dnsServer, ip.As4())
	defer func() {
		cancel()
		httpListener.Close()
		tlsListener.Close()
		udpServer.Close()
		dnsServer.Close()
		servers.Wait()
	}()

	var truths []researchtrace.TruthFlow
	var clients []io.Closer
	defer func() {
		for _, client := range clients {
			client.Close()
		}
	}()

	// Resolve two names to one address. Both answers remain live, so an
	// address-wide fallback must either guess or explicitly abstain.
	queryDNS(dnsAddr, "alpha.lab.test")
	alpha, err := tlsClient(tlsAddr, "alpha.lab.test")
	if err != nil {
		fatal(err)
	}
	clients = append(clients, alpha)
	truths = append(truths, truth("tls-alpha", "tcp", alpha.LocalAddr(), alpha.RemoteAddr(), "alpha.lab.test", "shared-ip-tls-sni"))

	queryDNS(dnsAddr, "beta.lab.test")
	beta, err := tlsClient(tlsAddr, "beta.lab.test")
	if err != nil {
		fatal(err)
	}
	clients = append(clients, beta)
	truths = append(truths, truth("tls-beta", "tcp", beta.LocalAddr(), beta.RemoteAddr(), "beta.lab.test", "shared-ip-tls-sni"))

	// This application intends alpha but withholds SNI. The latest-answer DNS
	// baseline guesses beta; an ambiguity-aware policy should abstain.
	fallback, err := tlsClient(tlsAddr, "")
	if err != nil {
		fatal(err)
	}
	clients = append(clients, fallback)
	truths = append(truths, truth("tls-alpha-no-sni", "tcp", fallback.LocalAddr(), fallback.RemoteAddr(), "alpha.lab.test", "shared-ip-no-sni"))

	clear, err := net.Dial("tcp4", httpAddr)
	if err != nil {
		fatal(err)
	}
	if _, err := io.WriteString(clear, "GET / HTTP/1.1\r\nHost: clear.lab.test\r\nConnection: keep-alive\r\n\r\n"); err != nil {
		fatal(err)
	}
	clients = append(clients, clear)
	truths = append(truths, truth("http-clear", "tcp", clear.LocalAddr(), clear.RemoteAddr(), "clear.lab.test", "clear-http-host"))

	udpClient, err := net.Dial("udp4", udpAddr)
	if err != nil {
		fatal(err)
	}
	if _, err := udpClient.Write([]byte("identity-lab direct UDP")); err != nil {
		fatal(err)
	}
	clients = append(clients, udpClient)
	truths = append(truths, truth("udp-direct", "udp", udpClient.LocalAddr(), udpClient.RemoteAddr(), "direct.lab.test", "no-visible-name"))

	if err := writeTruth(*out, truths); err != nil {
		fatal(err)
	}
	time.Sleep(*hold)
	fmt.Printf("identity-lab: wrote %d independently labelled flows to %s\n", len(truths), *out)
}

func serveTCP(ctx context.Context, wg *sync.WaitGroup, listener net.Listener) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
}

func serveUDP(ctx context.Context, wg *sync.WaitGroup, conn net.PacketConn) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			if _, _, err := conn.ReadFrom(buf); err != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
}

func serveDNS(ctx context.Context, wg *sync.WaitGroup, conn net.PacketConn, answer [4]byte) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			response, err := dnsResponse(buf[:n], answer)
			if err == nil {
				_, _ = conn.WriteTo(response, peer)
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
}

func queryDNS(server, name string) {
	conn, err := net.Dial("udp4", server)
	if err != nil {
		fatal(err)
	}
	defer conn.Close()
	idBytes := make([]byte, 2)
	if _, err := rand.Read(idBytes); err != nil {
		fatal(err)
	}
	query := make([]byte, 12)
	copy(query[:2], idBytes)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range splitName(name) {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	if _, err := conn.Write(query); err != nil {
		fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1500)); err != nil {
		fatal(fmt.Errorf("controlled DNS exchange for %s: %w", name, err))
	}
}

func dnsResponse(query []byte, answer [4]byte) ([]byte, error) {
	if len(query) < 17 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, errors.New("invalid DNS query")
	}
	end := 12
	for {
		if end >= len(query) {
			return nil, errors.New("truncated DNS name")
		}
		n := int(query[end])
		end++
		if n == 0 {
			break
		}
		if n > 63 || end+n > len(query) {
			return nil, errors.New("invalid DNS label")
		}
		end += n
	}
	if end+4 > len(query) {
		return nil, errors.New("truncated DNS question")
	}
	end += 4
	response := append([]byte(nil), query[:end]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, 0xc0, 0x0c, 0, 1, 0, 1)
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 60)
	response = append(response, ttl...)
	response = append(response, 0, 4)
	response = append(response, answer[:]...)
	return response, nil
}

func tlsClient(address, serverName string) (*tls.Conn, error) {
	raw, err := net.Dial("tcp4", address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: serverName, MinVersion: tls.VersionTLS12}) // controlled self-signed lab
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: encrypted-not-observable.lab.test\r\n\r\n"); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func truth(id, proto string, local, remote net.Addr, name, condition string) researchtrace.TruthFlow {
	localAddr := addrPort(local)
	remoteAddr := addrPort(remote)
	return researchtrace.TruthFlow{
		Type: "truth", At: time.Now().Unix(), FlowID: id, Proto: proto,
		LocalIP: localAddr.Addr().Unmap().String(), LocalPort: localAddr.Port(),
		RemoteIP: remoteAddr.Addr().Unmap().String(), RemotePort: remoteAddr.Port(),
		Truth: name, TruthSource: "workload_manifest", Condition: condition,
	}
}

func addrPort(addr net.Addr) netip.AddrPort {
	value, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		fatal(err)
	}
	return value
}

func splitName(name string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	return labels
}

func writeTruth(path string, truths []researchtrace.TruthFlow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, truth := range truths {
		if err := enc.Encode(truth); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

func certificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "ohmyosi identity lab"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "identity-lab:", err)
	os.Exit(1)
}

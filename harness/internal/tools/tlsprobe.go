package tools

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// TLSProbe performs a TLS handshake and reports certificate details. It reads
// the certificate without validating the chain (InsecureSkipVerify), because a
// recon tool must report on self-signed and mis-issued certs too; it makes no
// trust decision, it only observes.
type TLSProbe struct{}

func (TLSProbe) Name() string   { return "tls_probe" }
func (TLSProbe) Mutating() bool { return false }

func (TLSProbe) Description() string {
	return "TLS handshake against an in-scope host:port; returns certificate subject, issuer, SANs, validity, protocol and cipher suite."
}

func (TLSProbe) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"host": map[string]any{"type": "string", "description": "In-scope host name or IP"},
			"port": map[string]any{"type": "integer", "description": "TCP port (default 443)"},
		},
		"required": []any{"host"},
	}
}

func (TLSProbe) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	host := strArg(args, "host")
	port := intArg(args, "port", 443)
	if host == "" {
		return core.Result{Tool: "tls_probe", Allowed: false, Reason: "missing required argument 'host'"}
	}
	if port < 1 || port > 65535 {
		return core.Result{Tool: "tls_probe", Allowed: false, Reason: fmt.Sprintf("invalid port %d", port)}
	}
	ok, reason := s.CheckTarget(ctx, host, &port)
	if !ok {
		return core.Result{Tool: "tls_probe", Target: host, Allowed: false, Reason: reason}
	}

	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return core.Result{Tool: "tls_probe", Target: host, Allowed: true,
			Reason: "connect failed: " + err.Error()}
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		return core.Result{Tool: "tls_probe", Target: host, Allowed: true,
			Reason: "TLS handshake failed: " + err.Error()}
	}

	cs := conn.ConnectionState()
	leaf := cs.PeerCertificates[0]
	var sanIPs []string
	for _, ip := range leaf.IPAddresses {
		sanIPs = append(sanIPs, ip.String())
	}
	return core.Result{Tool: "tls_probe", Target: fmt.Sprintf("%s:%d", host, port), Allowed: true,
		Payload: map[string]any{
			"common_name":  leaf.Subject.CommonName,
			"subject":      leaf.Subject.String(),
			"issuer":       leaf.Issuer.CommonName,
			"san_dns":      leaf.DNSNames,
			"san_ips":      sanIPs,
			"not_before":   leaf.NotBefore.UTC().Format(time.RFC3339),
			"not_after":    leaf.NotAfter.UTC().Format(time.RFC3339),
			"expired":      time.Now().After(leaf.NotAfter),
			"tls_version":  protoName(cs.Version),
			"cipher_suite": tls.CipherSuiteName(cs.CipherSuite),
			"chain_length": len(cs.PeerCertificates),
		}}
}

func protoName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

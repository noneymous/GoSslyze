package gosslyze

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type Scanner struct {
	ctx    context.Context // Context
	path   string          // Binary path
	args   []string        // Args for SSLyze
	Result HostResult      // Scan result
}

// Constructor for SSLyze wrapper
func NewScanner(sslyzePath string, args ...string) Scanner {

	// Initialize values
	scanner := Scanner{
		path: sslyzePath,
		args: args,
	}

	// Adds a default context to the scanner
	if scanner.ctx == nil {
		scanner.ctx = context.Background()
	}

	return scanner
}

func (s *Scanner) Run() (*HostResult, error) {
	var stdout, stderr bytes.Buffer

	// Enable json output and let it be output to stdout instead of a file.
	s.args = append(s.args, "--json_out=-")

	// Prepare the command
	cmd := exec.Command(s.path, s.args...)

	// Set output and error buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Exec the command
	errStart := cmd.Start()
	if errStart != nil {
		return nil, errStart
	}

	// Make a goroutine to notify the select when the scan is done.
	// The channel has to be buffered in order to allow the goroutine to finish when the ctx.Timeout is reached before
	// the command finishes.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-s.ctx.Done():
		// Context was done before the scan was finished.
		// The process is killed and a timeout error is returned.
		_ = cmd.Process.Kill()

		return nil, errors.New("SSLyze scan timed out")
	case <-done:
		// Scan finished before timeout.
		if stderr.Len() > 0 {
			return nil, errors.New(strings.Trim(stderr.String(), ".\n"))
		}

		// Parse returned data
		result, errParse := Parse(stdout.Bytes())
		if errParse != nil {
			return nil, fmt.Errorf("unable to parse SSLyze output: %v", errParse)
		}

		return result, nil
	}
}

// WithTarget sets the target for the scanner.
func (s *Scanner) WithTarget(target string, port int) {
	s.args = append(s.args, fmt.Sprintf("%s:%d", target, port))
}

// WithContext adds a context to the scanner, to make it cancellable and able to timeout.
func (s *Scanner) WithContext(ctx context.Context) {
	s.ctx = ctx
}

// WithMozillaConfig adds a check for the server's TLS configurations against one of Mozilla's TLS
// configuration. Available options are: "modern", "intermediate", "old" and "disable".
// Set to "intermediate" per default. Pass "disable" to disable this check.
func (s *Scanner) WithMozillaConfig(config string) {
	s.args = append(s.args, fmt.Sprintf("--mozilla_config=%s", config))
}

// Update the default trust stores used by SSLyze. The latest stores will be downloaded from
// https://github.com/nabla-c0d3/trust_stores_observatory. This option is meant to be used
// separately, and will silence any other command line option supplied to SSLyze.
func (s *Scanner) UpdateTrustStores() {
	s.args = []string{"--update_trust_stores"}
}

// WithTargetsFile will read the list of targets to scan from the file defined by the 'path' parameter. The file should
// have a host and port per line with the format 'host:port'
func (s *Scanner) WithTargetsFile(path string) {
	s.args = append(s.args, fmt.Sprintf("--targets_in=%s", path))
}

// WithSlowConnection reduces the number of concurrent connections. The scan will therefore be slower but more reliable
// if the connection between the host and server is slow or the server can not handle many connections.
func (s *Scanner) WithSlowConnection() {
	s.args = append(s.args, "--slow_connection")
}

// WithHttpsTunnel tunnels all traffic to the target server(s) through an HTTP CONNECT proxy. HTTP_TUNNEL should be the
// proxy's URL: 'http://USER:PW@HOST:PORT/' (or 'http://HOST:PORT', if no authentication is required).
// For proxies requiring authentication, only basic authentication is supported.
func (s *Scanner) WithHttpsTunnel(proxy string) {
	s.args = append(s.args, fmt.Sprintf("--https_tunnel=%s", proxy))
}

// WithStartTls will perform a StartTLS handshake when connecting to the target server(s). 'prot' should be one of the following:
// smtp, xmpp, xmpp_server, pop3, ftp, imap, ldap, rdp, postgres, auto
// Where auto will deduce the protocol from the supplied port number.
func (s *Scanner) WithStartTls(prot string) {
	s.args = append(s.args, fmt.Sprintf("--starttls %s", prot))
}

// WithXmppTo should be set with 'starttls xmpp'. The parameter should be the hostname that is supposed to be set in the
// 'to' field of the XMPP stream. Default is the server's hostname.
func (s *Scanner) WithXmppTo(xmppTo string) {
	s.args = append(s.args, fmt.Sprintf("--xmpp_to=%s", xmppTo))
}

// WithSni adds server name indication usage. Only affects tls1.0+ connections.
// NOTE: SNI seems a bit buggy, it is neither possible to specify multiple SNI-hostnames for a single target scan nor is
// it possible to set a SNI-hostname for one target in a multi target scan.
func (s *Scanner) WithSni(sni string) {
	s.args = append(s.args, fmt.Sprintf("--sni=%s", sni))
}

// WithRenegotiation test the server(s) for client-initiated renegotiation and secure renegotiation support.
func (s *Scanner) WithRenegotiation() {
	s.args = append(s.args, "--reneg")
}

// CheckHeartbleed test the server(s) for the OpenSSL Heartbleed vulnerability.
func (s *Scanner) WithHeartbleed() {
	s.args = append(s.args, "--heartbleed")
}

// WithRobot test the server(s) for the "Return Of Bleichenbacher's Oracle Threat" vulnerability.
func (s *Scanner) WithRobot() {
	s.args = append(s.args, "--robot")
}

// CheckCompression test the server(s) for Zlib compression support.
func (s *Scanner) WithCompression() {
	s.args = append(s.args, "--compression")
}

// WithHttpHeaders will test the server(s) for security related HTTP headers like "HTTP Strict Transport Security" (HSTS)
// and "HTTP Public Key Pinning" (HPKP) within the response. Does also compute the HPKP pins for the server(s) current certificate chain.
func (s *Scanner) WithHttpHeaders() {
	s.args = append(s.args, "--http_headers")
}

// WithCcs test the server(s) for the OpenSSL CCS injection vulnerability (CVE-2014-0224).
func (s *Scanner) WithCcs() {
	s.args = append(s.args, "--openssl_ccs")
}

// WithEarlyData test the server(s) for TLS1.3 early data support. Does only work with HTTPS server(s).
func (s *Scanner) WithEarlyData() {
	s.args = append(s.args, "--early_data")
}

// WithFallback test the server(s) for support of the TLS_FALLBACK_SCSV ciphers suite which prevents downgrade attacks.
func (s *Scanner) WithFallback() {
	s.args = append(s.args, "--fallback")
}

// WithEllipticCurves test the server(s) for supported elliptic curves.
func (s *Scanner) WithEllipticCurves() {
	s.args = append(s.args, "--elliptic_curves")
}

// WithResume tests the server(s) for session resumption support using session IDs and TLS session tickets (RFC 5077).
func (s *Scanner) WithResume() {
	s.args = append(s.args, "--resum")
}

// WithResumeAttempts is to be used with WithResume. Sets the number of session resumptions (both with Session IDs and TLS Tickets)
// that SSLyze should attempt. The default value is 5, but a higher value such as 100 can be used to get a more accurate
// measure of how often session resumption succeeds or fails with the server.
func (s *Scanner) WithResumeAttempts(resum_attempts int) {
	s.args = append(s.args, fmt.Sprintf("--resum_attempts=%d", resum_attempts))
}

// WithCertInfo check validity of server(s) certificate(s) against trust stores (mozzila , apple etc), check for OCSP stapling support.
func (s *Scanner) WithCertInfo() {
	s.args = append(s.args, "--certinfo")
}

// WithCaFile sets the path to a local trust store file (with root certificates in PEM format) to verify the
// validity of the server(s) certificate's chain(s) against.
func (s *Scanner) WithCaFile(path string) {
	s.args = append(s.args, fmt.Sprintf("--certinfo_ca_file=%s", path))
}

// WithClientCert sets the client certificate chain for authentication. The certificates must be in PEM format and must
// be sorted starting with the subject's client certificate, followed by intermediate CA certificates if applicable.
// Additionally the path of the client's private key file is set, as it is needed for client authentication as well.
func (s *Scanner) WithClientCert(chainPath string, keyPath string) {
	s.args = append(s.args, fmt.Sprintf("--cert=%s", chainPath))
	s.args = append(s.args, fmt.Sprintf("--key=%s", keyPath))
}

// WithClientKeyFormat sets the format of the client's private key file. either "DER" or "PEM" (default)
func (s *Scanner) WithClientKeyFormat(format string) {
	s.args = append(s.args, fmt.Sprintf("--keyform=%s", format))
}

// WithClientKeyPass sets the passphrase of the client's private key.
func (s *Scanner) WithClientKeyPass(pass string) {
	s.args = append(s.args, fmt.Sprintf("--pass=%s", pass))
}

// WithSslV2 list the SSL 2.0 OpenSSL ciphers suites.
func (s *Scanner) WithSslV2() {
	s.args = append(s.args, "--sslv2")
}

// WithSslV3 list the SSL 3.0 OpenSSL ciphers suites.
func (s *Scanner) WithSslV3() {
	s.args = append(s.args, "--sslv3")
}

// WithTlsV1 list the tls 1.0 OpenSSL ciphers suites.
func (s *Scanner) WithTlsV1() {
	s.args = append(s.args, "--tlsv1")
}

// WithTlsV1_1 list the tls 1.1 OpenSSL ciphers suites.
func (s *Scanner) WithTlsV1_1() {
	s.args = append(s.args, "--tlsv1_1")
}

// WithTlsV1_2 list the tls 1.2 OpenSSL ciphers suites.
func (s *Scanner) WithTlsV1_2() {
	s.args = append(s.args, "--tlsv1_2")
}

// WithTlsV1_3 list the tls 1.3 OpenSSL ciphers suites.
func (s *Scanner) WithTlsV1_3() {
	s.args = append(s.args, "--tlsv1_3")
}

// Parse converts SSLyze json output to internal data structure
func Parse(content []byte) (*HostResult, error) {

	result := &HostResult{}

	// Try to parse the output data to internal structure
	errUnmarshal := json.Unmarshal(content, result)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}

	return result, nil
}

package gosslyze

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"time"
)

// Outermost structures
type HostResult struct {
	InvalidTargets        []ConnectivityError `json:"invalid_server_strings"`
	Targets               []Target            `json:"server_scan_results"`
	Url                   string              `json:"sslyze_url"`
	Version               string              `json:"sslyze_version"`
	DateScansCompleted    UtcTime             `json:"date_scans_completed"`
	DateScansStarted      UtcTime             `json:"date_scans_started"`
	ComplianceTestDetails string              // Details of Mozilla's recommended config check
}

// Server errors
type ConnectivityError struct {
	Server string `json:"server_string"`
	Error  string `json:"error_message"`
}

// Scan results

type Target struct {
	ConnectivityErrorTrace string         `json:"connectivity_error_trace"`
	ConnectivityResult     Probing        `json:"connectivity_result"`
	ConnectivityStatus     string         `json:"connectivity_status"`
	NetworkConfig          NetworkConfig  `json:"network_configuration"`
	ScanResult             CommandResults `json:"scan_result"`
	ScanStatus             string         `json:"scan_status"`
	ServerLocation         ServerLocation `json:"server_location"`
	UUID                   string         `json:"uuid"`
}

type NetworkConfig struct {
	NetworkMaxRetries       int                   `json:"network_max_retries"`
	NetworkTimeout          int                   `json:"network_timeout"`
	ClientAuthCredentials   ClientAuthCredentials `json:"tls_client_auth_credentials"`
	OpportunisticEncryption string                `json:"tls_opportunistic_encryption"`
	Sni                     string                `json:"tls_server_name_indication"`
	XmppToHostname          string                `json:"xmpp_to_hostname"`
}

type ClientAuthCredentials struct {
	CertificateChainPath string `json:"certificate_chain_path"`
	KeyPath              string `json:"key_path"`
	KeyType              int    `json:"key_type"`
}

type ServerLocation struct {
	ConnectionType string            `json:"connection_type"`
	Hostname       string            `json:"hostname"`
	Ip             string            `json:"ip_address"`
	Port           int               `json:"port"`
	HttpProx       HttpProxySettings `json:"http_proxy_settings"`
}

type HttpProxySettings struct {
	Hostname          string `json:"hostname"`
	Port              int    `json:"port"`
	BasicAuthUser     string `json:"basic_auth_user"`
	BasicAuthPassword string `json:"basic_auth_password"`
}

type Probing struct {
	SupportedCipher            string `json:"cipher_suite_supported"`
	ClientAuthRequirement      string `json:"client_auth_requirement"`
	HighestTlsVersionSupported string `json:"highest_tls_version_supported"`
	SupportedEcdhKeyExchange   bool   `json:"supports_ecdh_key_exchange"`
}

// Command results

type StandardErrorStatus struct {
	ErrorReason string `json:"error_reason"`
	ErrorTrace  string `json:"error_trace"`
	Status      string `json:"status"`
}

type CommandResults struct {
	IsCompliant    bool            // Check if compliant against Mozilla's recommended config
	CertInfo       *CertInfo       `json:"certificate_info"`
	EllipticCurves *EllipticCurves `json:"elliptic_curves"`

	Heartbleed *struct {
		StandardErrorStatus
		Result *struct {
			IsVulnerable bool `json:"is_vulnerable_to_heartbleed"`
		} `json:"result"`
	} `json:"heartbleed"`

	OpensslCcs *struct {
		StandardErrorStatus
		Result *struct {
			IsVulnerable bool `json:"is_vulnerable_to_ccs_injection"`
		} `json:"result"`
	} `json:"openssl_ccs_injection"`

	Robot *struct {
		StandardErrorStatus
		Result *struct {
			IsVulnerable string `json:"robot_result"`
		} `json:"result"`
	} `json:"robot"`

	Renegotiation *struct {
		StandardErrorStatus
		Result *Renegotiation `json:"result"`
	} `json:"session_renegotiation"`

	Resumption *struct {
		StandardErrorStatus
		Result *Resumption `json:"result"`
	} `json:"session_resumption"`

	HttpHeaders *struct {
		StandardErrorStatus
		Result *HttpHeaders `json:"result"`
	} `json:"http_headers"`

	SslV2   *Protocol `json:"ssl_2_0_cipher_suites"`
	SslV3   *Protocol `json:"ssl_3_0_cipher_suites"`
	TlsV1_0 *Protocol `json:"tls_1_0_cipher_suites"`
	TlsV1_1 *Protocol `json:"tls_1_1_cipher_suites"`
	TlsV1_2 *Protocol `json:"tls_1_2_cipher_suites"`
	TlsV1_3 *Protocol `json:"tls_1_3_cipher_suites"`

	EarlyData *struct {
		StandardErrorStatus
		Result *struct {
			IsSupported bool `json:"supports_early_data"`
		} `json:"result"`
	} `json:"tls_1_3_early_data"`

	Compression *struct {
		StandardErrorStatus
		Result *struct {
			IsSupported bool `json:"supports_compression"`
		} `json:"result"`
	} `json:"tls_compression"`

	Fallback *struct {
		StandardErrorStatus
		Result *struct {
			IsSupported bool `json:"supports_fallback_scsv"`
		} `json:"result"`
	} `json:"tls_fallback_scsv"`
}

// Certificate Information

type CertInfo struct {
	ErrorReason string         `json:"error_reason"`
	ErrorTrace  string         `json:"error_trace"`
	Result      CertInfoResult `json:"result"`
	Status      string         `json:"status"`
}

type CertInfoResult struct {
	Deployments  []Deployment `json:"certificate_deployments"`
	HostnameUsed string       `json:"hostname_used_for_server_name_indication"`
}

type Deployment struct {
	StapleExtension   bool             `json:"leaf_certificate_has_must_staple_extension"`
	IsLeafEv          bool             `json:"leaf_certificate_is_ev"`
	SctsCount         int              `json:"leaf_certificate_signed_certificate_timestamps_count"`
	MatchHostname     bool             `json:"leaf_certificate_subject_matches_hostname"` // Removed in Sslyze 6.0.0
	OcspResponse      *OscpResponse    `json:"ocsp_response"`
	OcspIsTrusted     bool             `json:"ocsp_response_is_trusted"`
	PathValidation    []PathValidation `json:"path_validation_results"`
	CertificateChain  []Certificate    `json:"received_certificate_chain"`
	HasAnchor         bool             `json:"received_chain_contains_anchor_certificate"`
	HasValidOrder     bool             `json:"received_chain_has_valid_order"`
	VerifiedCertChain *[]Certificate   `json:"verified_certificate_chain"`
	SymantecDistrust  bool             `json:"verified_chain_has_legacy_symantec_anchor"`
	HasSha1           bool             `json:"verified_chain_has_sha1_signature"`
}

type PathValidation struct {
	ValidationError string `json:"validation_error"`     // Previously named "openssl_error_string" in Sslyze < 6.0.0
	OpenSslError    string `json:"openssl_error_string"` // Renamed to "validation_error" in Sslyze < 6.0.0

	TrustStore           TrustStore     `json:"trust_store"`
	VerifiedChain        *[]Certificate `json:"verified_certificate_chain"`
	ValidationSuccessful bool           `json:"was_validation_successful"`
}

type Certificate struct {
	Pem               string      `json:"as_pem"`
	FingerprintSha1   string      `json:"fingerprint_sha1"`
	FingerprintSha256 string      `json:"fingerprint_sha256"`
	HpkpPin           string      `json:"hpkp_pin"`
	Issuer            Entity      `json:"issuer"`
	NotValidAfter     UtcTime     `json:"not_valid_after"`
	NotValidBefore    UtcTime     `json:"not_valid_before"`
	PublicKey         PublicKey   `json:"public_key"`
	Serial            big.Int     `json:"serial_number"`
	SignatureAlg      Oid         `json:"signature_algorithm_oid"`
	SignatureHashAlgo SigHashAlgo `json:"signature_hash_algorithm"`
	Subject           Entity      `json:"subject"`
	SubjectAltName    SubjAltName `json:"subject_alternative_name"`
}

type SigHashAlgo struct {
	DigestSize int    `json:"digest_size"`
	Name       string `json:"name"`
}

type Entity struct {
	Attributes *[]Attribute `json:"attributes"`     // Empty if Parsing error is set
	RfcString  string       `json:"rfc4514_string"` // Empty if Parsing error is set
}

type Attribute struct {

	// All OIDs: https://cryptography.io/en/latest/_modules/cryptography/x509/oid/
	Oid       Oid    `json:"oid"`
	RfcString string `json:"rfc4514_string"`
	Value     string `json:"value"`
}

type Oid struct {
	DotNotation string `json:"dotted_string"`
	Name        string `json:"name"`
}

type SubjAltName struct {
	DnsNames    []string `json:"dns_names"`
	IpAddresses []string `json:"ip_addresses"`
}

// UnmarshalJSON for the SubjAltName struct.
// Necessary because in older versions the "dns_names" is called "dns" and the "ip_addresses" is missing
func (s *SubjAltName) UnmarshalJSON(data []byte) error {

	// First, deserialize everything into a map of map
	var rawMap map[string]*json.RawMessage
	errUnmar := json.Unmarshal(data, &rawMap)
	if errUnmar != nil {
		return errUnmar
	}

	// Handle the ip addresses
	rawIpData, ok := rawMap["ip_addresses"]
	if !ok || rawIpData == nil || len(*rawIpData) == 0 {
		s.IpAddresses = []string{} // Create empty list if ip_addresses field is missing, empty or nil
	} else {
		var ip []string
		errUnmar = json.Unmarshal(*rawIpData, &ip)
		if errUnmar != nil {
			return errUnmar
		}
		s.IpAddresses = ip
	}

	// Handle "dns_names" (or "dns") field
	rawDnsData, ok := rawMap["dns"]
	if !ok {
		rawDnsData, ok = rawMap["dns_names"]
		if !ok || rawDnsData == nil || len(*rawDnsData) == 0 {
			s.DnsNames = []string{} // Create empty list if "dns_names" / "dns" field is missing, empty or nil
		}
	} else {
		var dns []string
		errUnmar = json.Unmarshal(*rawDnsData, &dns)
		if errUnmar != nil {
			return errUnmar
		}
		s.DnsNames = dns
	}

	return nil
}

type PublicKey struct {
	Algorithm      string  `json:"algorithm"`
	Curve          string  `json:"ec_curve_name"`
	Exponent       int     `json:"rsa_e"`
	Size           int     `json:"key_size"`
	RsaN           big.Int `json:"rsa_n"`
	EllipticCurveX big.Int `json:"ec_x"`
	EllipticCurveY big.Int `json:"ec_y"`
}

type TrustStore struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Version string `json:"version"`
	EvOids  *[]Oid `json:"ev_oids"`
}

type OscpResponse struct {
	Status            string  `json:"status"`
	Type              string  `json:"type"`
	Version           int     `json:"version"`
	ResponderId       string  `json:"responder_id"`
	ProducedAt        UtcTime `json:"produced_at"`
	CertificateStatus string  `json:"certificate_status"`
	ThisUpdate        UtcTime `json:"this_update"`
	NextUpdate        UtcTime `json:"next_update"`
	HashAlgorithm     string  `json:"hash_algorithm"`
	IssuerNameHash    string  `json:"issuer_name_hash"`
	IssuerKeyHash     string  `json:"issuer_key_hash"`
	SerialNumber      big.Int `json:"serial_number"`
}

// Elliptic Curves

type EllipticCurves struct {
	StandardErrorStatus
	Result *EllipticCurveResult `json:"result"`
}

type EllipticCurveResult struct {
	SupportedCurves        []Curve `json:"supported_curves"`
	RejectedCurves         []Curve `json:"rejected_curves"`
	SupportEcdhKeyExchange bool    `json:"supports_ecdh_key_exchange"`
}

type Curve struct {
	Name       string `json:"name"`
	OpenSslNid int    `json:"openssl_nid"`
}

// Cipher Suites

type Protocol struct {
	StandardErrorStatus
	Result *CipherResult `json:"result"`
}

type CipherResult struct {
	AcceptedCiphers   []AcceptedCipher `json:"accepted_cipher_suites"`
	RejectedCiphers   []RejectedCipher `json:"rejected_cipher_suites"`
	SupportTlsVersion bool             `json:"is_tls_version_supported"`
	TlsVersion        string           `json:"tls_version_used"`
}

type RejectedCipher struct {
	Cipher Cipher `json:"cipher_suite"`
	Error  string `json:"error_message"`
}

type AcceptedCipher struct {
	Cipher       Cipher           `json:"cipher_suite"`
	EphemeralKey EphemeralKeyInfo `json:"ephemeral_key"` // Optional!, but it's an interface
}

type Cipher struct {
	IsAnonymous bool   `json:"is_anonymous"`
	KeySize     int    `json:"key_size"`
	Name        string `json:"name"`
	OpensslName string `json:"openssl_name"`
}

type EphemeralKeyInfo interface{}

type BaseKeyInfo struct {
	EphemeralKeyInfo
	TypeName    string `json:"type_name"`
	Size        int    `json:"size"`
	PublicBytes []byte `json:"public_bytes"`
}

type EcdhKeyInfo struct {
	BaseKeyInfo
	CurveName string `json:"curve_name"`
}

type NistEcdhKeyInfo struct {
	EcdhKeyInfo
	X []byte `json:"x"`
	Y []byte `json:"y"`
}

type DhKeyInfo struct {
	BaseKeyInfo
	Prime     []byte `json:"prime"`
	Generator []byte `json:"generator"`
}

// fieldsMatch checks for the existence of all the 'keys' in the map. The map also needs to have no other keys aside
// from the provided ones.
func fieldsMatch(m map[string]*json.RawMessage, keys ...string) bool {

	// Remove keys that have null value
	for key, elem := range m {
		if elem == nil {
			delete(m, key)
		}
	}
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {

		if _, ok := m[k]; !ok {
			return false
		}
	}

	return true
}

func (c *AcceptedCipher) UnmarshalJSON(data []byte) error {

	// First, deserialize everything into a map of map
	var rawMap map[string]*json.RawMessage
	errUnmar := json.Unmarshal(data, &rawMap)
	if errUnmar != nil {
		return errUnmar
	}

	// Handle the cipher suite first
	rawCipherData, ok := rawMap["cipher_suite"]
	if !ok {
		return errors.New("cipher_suite field missing in AcceptedCipher")
	}
	if rawCipherData == nil {
		return errors.New("cipher_suite field is nil in AcceptedCipher")
	}

	c.Cipher = Cipher{}
	errUnmar = json.Unmarshal(*rawCipherData, &c.Cipher)
	if errUnmar != nil {
		return errUnmar
	}

	// Handle the ephemeral key info
	rawKeyData, ok := rawMap["ephemeral_key"]
	if !ok {
		c.EphemeralKey = nil
		return nil
	}
	if rawKeyData == nil {
		return nil
	}
	var rawKeyInfo map[string]*json.RawMessage
	errUnmar = json.Unmarshal(*rawKeyData, &rawKeyInfo)
	if errUnmar != nil {
		return errUnmar
	}

	// See what fields exist in order to determine the concrete struct we want to unmarshal to.
	// BaseKeyInfo
	if fieldsMatch(rawKeyInfo, "type_name", "size", "public_bytes") {
		base := &BaseKeyInfo{}
		errUnmar := json.Unmarshal(*rawKeyData, base)
		if errUnmar != nil {
			return errUnmar
		}
		c.EphemeralKey = base
		return nil
	}

	// EcdhKeyInfo
	if fieldsMatch(rawKeyInfo, "type_name", "size", "public_bytes", "curve_name") {
		ecdh := &EcdhKeyInfo{}
		errUnmar := json.Unmarshal(*rawKeyData, ecdh)
		if errUnmar != nil {
			return errUnmar
		}
		c.EphemeralKey = ecdh
		return nil
	}

	// NistEcdhKeyInfo
	if fieldsMatch(rawKeyInfo, "type_name", "size", "public_bytes", "curve_name", "x", "y") {
		nist := &NistEcdhKeyInfo{}
		errUnmar := json.Unmarshal(*rawKeyData, nist)
		if errUnmar != nil {
			return errUnmar
		}
		c.EphemeralKey = nist
		return nil
	}

	// DhKeyInfo
	if fieldsMatch(rawKeyInfo, "type_name", "size", "public_bytes", "prime", "generator") {
		dh := &DhKeyInfo{}
		errUnmar := json.Unmarshal(*rawKeyData, dh)
		if errUnmar != nil {
			return errUnmar
		}
		c.EphemeralKey = dh
		return nil
	}

	// Create a new unmarshal error as we could not find a matching type.
	var e EphemeralKeyInfo
	return &json.UnmarshalTypeError{
		Value: string(data),
		Type:  reflect.TypeOf(e),
	}
}

// Session renegotiation & resumption

type Renegotiation struct {
	VulnerableToClientRenegotiation bool `json:"is_vulnerable_to_client_renegotiation_dos"`
	SupportsSecureRenegotiation     bool `json:"supports_secure_renegotiation"`
}

type Resumption struct {
	AttemptedIdResumptions           int    `json:"session_id_attempted_resumptions_count"`
	Result                           string `json:"session_id_resumption_result"`
	SuccessfulIdResumptions          int    `json:"session_id_successful_resumptions_count"`
	TicketAttemptedResumptionsCount  int    `json:"tls_ticket_attempted_resumptions_count"`
	TicketResumption                 string `json:"tls_ticket_resumption_result"`
	TicketSuccessfulResumptionsCount int    `json:"tls_ticket_successful_resumptions_count"`
}

type ResumptionRate struct {
	AttemptedIdResumptions  int `json:"attempted_session_id_resumptions_count"`
	SuccessfulIdResumptions int `json:"successful_session_id_resumptions_count"`
}

// Vulnerabilities & weaknesses

type HttpHeaders struct {
	ExpectedCt     *ExpectedCtHeader `json:"expect_ct_header"`
	ErrorTrace     string            `json:"http_error_trace"`
	PathRedirected string            `json:"http_path_redirected_to"`
	RequestSent    string            `json:"http_request_sent"`
	Hsts           *HstsHeader       `json:"strict_transport_security_header"`
}

type HstsHeader struct {
	Preload           bool `json:"preload"`
	IncludeSubdomains bool `json:"include_subdomains"`
	MaxAge            int  `json:"max_age"`
}

type ExpectedCtHeader struct {
	Enforce   bool   `json:"enforce"`
	MaxAge    int    `json:"max_age"`
	ReportUri string `json:"report_uri"`
}

// Helper struct, because some SSLyze versions (or their used Cryptography to be more precise) converts the time
// into UTC and removes the time zone information. Therefore, golang can no longer parse the input automatically..
var timeFormats = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02T15:04:05Z",
}

type UtcTime struct {
	String string
	Time   time.Time
}

func (ut *UtcTime) UnmarshalJSON(data []byte) error {
	d := strings.Trim(string(data), `"`)

	// Return Utc Zero time
	if len(d) == 0 || d == "null" {
		return nil
	}

	// Try different formats to parse time
	var t = time.Time{}
	var errParse error
	for _, format := range timeFormats {
		t, errParse = time.Parse(format, d)
		if errParse == nil {
			break
		}
	}

	// Return error if necessary
	if errParse != nil {
		return errParse
	}

	// Set UtcTime values
	ut.String = d
	ut.Time = t

	// Return without error
	return nil
}

func (ut *UtcTime) MarshalJSON() ([]byte, error) {
	stamp := fmt.Sprintf("\"%s\"", ut.Time.Format(timeFormats[0]))
	return []byte(stamp), nil
}

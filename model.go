package gosslyze

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Outermost structures
type HostResult struct {
	InvalidTargets []ConnectivityError `json:"server_connectivity_errors"`
	Targets        []Target            `json:"server_scan_results"`
	Url            string              `json:"sslyze_url"`
	Version        string              `json:"sslyze_version"`
	TotalScanTime  float64             `json:"total_scan_time"`
}

type ConnectivityError struct {
	Error  string `json:"error_message"`
	Server string `json:"server_string"`
}

type Target struct {
	ScanCommands   []string                `json:"scan_commands"`
	CommandErrors  map[string]CommandError `json:"scan_commands_errors"`          // The key is the name of the module
	ExtraArguments ExtraArguments          `json:"scan_commands_extra_arguments"` // Currently only certificate info https://github.com/nabla-c0d3/sslyze/blob/74ff239543c1e3208b347942f4470631d89a1c27/sslyze/scanner.py
	CommandResults CommandResults          `json:"scan_commands_results"`
	ServerInfo     ServerInfo              `json:"server_info"`
}

type CommandError struct {
	Trace  string `json:"exception_trace"`
	Reason string `json:"reason"`
}

type ExtraArguments struct {
	Certificate *CertificateExtraArguments `json:"certificate_info"`
}

type CertificateExtraArguments struct {
	CustomCaFile string `json:"custom_ca_file"`
}

// Server information

type ServerInfo struct {
	NetworkConfig  NetworkConfig  `json:"network_configuration"`
	ServerLocation ServerLocation `json:"server_location"`
	Probing        Probing        `json:"tls_probing_result"`
}

type NetworkConfig struct {
	NetworkMaxRetries       int                    `json:"network_max_retries"`
	NetworkTimeout          int                    `json:"network_timeout"`
	ClientAuthCredentials   *ClientAuthCredentials `json:"tls_client_auth_credentials"`
	OpportunisticEncryption *string                `json:"tls_opportunistic_encryption"`
	Sni                     string                 `json:"tls_server_name_indication"`
	XmppToHostname          *string                `json:"xmpp_to_hostname"`
}

type ClientAuthCredentials struct {
	CertificateChainPath string `json:"certificate_chain_path"`
	KeyPath              string `json:"key_path"`
	KeyPassword          string `json:"key_password"`
	KeyType              int    `json:"key_type"`
}

type ServerLocation struct {
	Hostname string `json:"hostname"`
	Ip       string `json:"ip_address"`
	Port     int    `json:"port"`
}

type Probing struct {
	SupportedCipher            string `json:"cipher_suite_supported"`
	ClientAuthRequirement      string `json:"client_auth_requirement"`
	HighestTlsVersionSupported string `json:"highest_tls_version_supported"`
}

// Command results

type CommandResults struct {
	CertInfo *CertInfo `json:"certificate_info"`

	SslV2   *Protocol `json:"ssl_2_0_cipher_suites"`
	SslV3   *Protocol `json:"ssl_3_0_cipher_suites"`
	TlsV1_0 *Protocol `json:"tls_1_0_cipher_suites"`
	TlsV1_1 *Protocol `json:"tls_1_1_cipher_suites"`
	TlsV1_2 *Protocol `json:"tls_1_2_cipher_suites"`
	TlsV1_3 *Protocol `json:"tls_1_3_cipher_suites"`

	Compression *struct {
		IsSupported bool `json:"supports_compression"`
	} `json:"tls_compression"`

	EarlyData *struct {
		IsSupported bool `json:"supports_early_data"`
	} `json:"tls_1_3_early_data"`

	OpensslCcs *struct {
		IsVulnerable bool `json:"is_vulnerable_to_ccs_injection"`
	} `json:"openssl_ccs_injection"`

	Fallback *struct {
		FallbackScsv bool `json:"supports_fallback_scsv"`
	} `json:"tls_fallback_scsv"`

	Heartbleed *struct {
		IsVulnerable bool `json:"is_vulnerable_to_heartbleed"`
	} `json:"heartbleed"`

	Robot *struct {
		RobotEnum string `json:"robot_result"`
	} `json:"robot"`

	HttpHeaders *HttpHeaders `json:"http_headers"`

	Renegotiation  *Renegotiation  `json:"session_renegotiation"`
	Resumption     *Resumption     `json:"session_resumption"`
	ResumptionRate *ResumptionRate `json:"session_resumption_rate"`
}

// Certificate Information

type CertInfo struct {
	HostnameUsed string       `json:"hostname_used_for_server_name_indication"`
	Deployments  []Deployment `json:"certificate_deployments"`
}

type Deployment struct {
	StapleExtension  bool             `json:"leaf_certificate_has_must_staple_extension"`
	IsLeafEv         bool             `json:"leaf_certificate_is_ev"`
	MatchHostname    bool             `json:"leaf_certificate_subject_matches_hostname"`
	SctsCount        *int             `json:"leaf_certificate_signed_certificate_timestamps_count"`
	OcspResponse     *OscpResponse    `json:"ocsp_response"`
	OcspIsTrusted    *bool            `json:"ocsp_response_is_trusted"`
	PathValidation   []PathValidation `json:"path_validation_results"`
	CertificateChain []Certificate    `json:"received_certificate_chain"`
	HasAnchor        *bool            `json:"received_chain_contains_anchor_certificate"`
	HasValidOrder    bool             `json:"received_chain_has_valid_order"`
	SymantecDistrust *bool            `json:"verified_chain_has_legacy_symantec_anchor"`
	HasSha1          *bool            `json:"verified_chain_has_sha1_signature"`
}

type PathValidation struct {
	TrustStore    TrustStore     `json:"trust_store"`
	VerifiedChain *[]Certificate `json:"verified_certificate_chain"`
	OpenSslError  *string        `json:"openssl_error_string"`
	// This is not actually part of the json result, because it's a method.
	// ValidationSuccessful bool         `json:"was_validation_successful"`
	//
	// ValidationSuccessful: len(VerifiedChain) > 0
}

type Certificate struct {
	Pem            string      `json:"as_pem"`
	HpkpPin        string      `json:"hpkp_pin"`
	Issuer         Entity      `json:"issuer"`
	NotAfter       UtcTime     `json:"notAfter"`
	NotBefore      UtcTime     `json:"notBefore"`
	PublicKey      PublicKey   `json:"publicKey"`
	Serial         string      `json:"serialNumber"`
	SignatureAlg   string      `json:"signatureAlgorithm"`
	Subject        Entity      `json:"subject"`
	SubjectAltName SubjAltName `json:"subjectAlternativeName"`
}

type Entity struct {
	Attributes   *[]Attribute `json:"attributes"`     // Empty if Parsing error is set
	RfcString    *string      `json:"rfc4514_string"` // Empty if Parsing error is set
	ParsingError *string      `json:"parsing_error"`
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
	Dns []string `json:"DNS"`
}

type PublicKey struct {
	Algorithm string `json:"algorithm"`
	Curve     string `json:"curve"`
	Exponent  string `json:"exponent"`
	Size      string `json:"size"`
}

type TrustStore struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Version string `json:"version"`
	EvOids  *[]Oid `json:"ev_oids"`
}

type OscpResponse struct {
	Status            string         `json:"status"`
	Type              string         `json:"type"`
	Version           int            `json:"version"`
	ResponderId       string         `json:"responder_id"`
	ProducedAt        UtcTime        `json:"produced_at"`
	CertificateStatus string         `json:"certificate_status"`
	ThisUpdate        UtcTime        `json:"this_update"`
	NextUpdate        UtcTime        `json:"next_update"`
	HashAlgorithm     string         `json:"hash_algorithm"`
	IssuerNameHash    string         `json:"issuer_name_hash"`
	IssuerKeyHash     string         `json:"issuer_key_hash"`
	SerialNumber      string         `json:"serial_number"`
	Extensions        []SctExtension `json:"extensions"` // Currently only SignedCertificateTimestampsExtension
}

type SctExtension struct {
	Scts []SignedCertificateTimestamp
}

type SignedCertificateTimestamp struct {
	Version string  `json:"version"`
	LogId   string  `json:"log_id"`
	Time    UtcTime `json:"timestamp"`
}

// Cipher Suites

type Protocol struct {
	AcceptedCiphers []AcceptedCipher `json:"accepted_cipher_suites"`
	TlsVersion      string           `json:"tls_version_used"`
	PreferredCipher *AcceptedCipher  `json:"cipher_suite_preferred_by_server"`
	RejectedCiphers []RejectedCipher `json:"rejected_cipher_suites"`
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
	Name        string `json:"name"`
	OpenSslName string `json:"openssl_name"`
	IsAnonymous bool   `json:"is_anonymous"`
	KeySize     int    `json:"key_size"`
}

type EphemeralKeyInfo interface{}

type BaseKeyInfo struct {
	EphemeralKeyInfo
	Type        int    `json:"type"`
	TypeName    string `json:"type_name"`
	Size        int    `json:"size"`
	PublicBytes []byte `json:"public_bytes"`
}

type EcDhKeyInfo struct {
	BaseKeyInfo
	Curve     int    `json:"curve"`
	CurveName string `json:"curve_name"`
}

type NistEcDhKeyInfo struct {
	EcDhKeyInfo
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

	// Handle the the ephemeral key info
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
	if fieldsMatch(rawKeyInfo, "type", "type_name", "size", "public_bytes") {
		base := &BaseKeyInfo{}
		errUnmar := json.Unmarshal(*rawKeyData, base)
		if errUnmar != nil {
			return errUnmar
		}
		c.EphemeralKey = base
		return nil
	}
	// EcDhKeyInfo
	if fieldsMatch(rawKeyInfo, "type", "type_name", "size", "public_bytes", "curve", "curve_name") {
		ecdh := &EcDhKeyInfo{}
		errUnmar := json.Unmarshal(*rawKeyData, ecdh)
		if errUnmar != nil {
			return errUnmar
		}
		c.EphemeralKey = ecdh
		return nil
	}
	// NistEcDhKeyInfo
	if fieldsMatch(rawKeyInfo, "type", "type_name", "size", "public_bytes", "curve", "curve_name", "x", "y") {
		nist := &NistEcDhKeyInfo{}
		errUnmar := json.Unmarshal(*rawKeyData, nist)
		if errUnmar != nil {
			return errUnmar
		}
		c.EphemeralKey = nist
		return nil
	}
	// DhKeyInfo
	if fieldsMatch(rawKeyInfo, "type", "type_name", "size", "public_bytes", "prime", "generator") {
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
	AcceptsClientRenegotiation  bool `json:"accepts_client_renegotiation"`
	SupportsSecureRenegotiation bool `json:"supports_secure_renegotiation"`
}

type Resumption struct {
	AttemptedIdResumptions  int    `json:"attempted_session_id_resumptions_count"`
	SuccessfulIdResumptions int    `json:"successful_session_id_resumptions_count"`
	TicketResumption        string `json:"tls_ticket_resumption_result"`
	// These two are not actually part of the json result, because they're methods.
	// TicketResumptionSupported *bool `json:"is_tls_ticket_resumption_supported"`
	// IdResumptionSupported *bool `json:"is_session_id_resumption_supported"`
	//
	// TicketResumptionSupported: (TicketResumption == TicketResumptionSuccess)
	// IdResumptionSupported: (AttemptedIdResumptions == SuccessfulIdResumptions)

}

type ResumptionRate struct {
	AttemptedIdResumptions  int `json:"attempted_session_id_resumptions_count"`
	SuccessfulIdResumptions int `json:"successful_session_id_resumptions_count"`
}

// Vulnerabilities & weaknesses

type HttpHeaders struct {
	Hsts           *HstsHeader       `json:"strict_transport_security_header"`
	Hpkp           *HpkpHeader       `json:"public_key_pins_header"`
	HpkpReportOnly *HpkpHeader       `json:"public_key_pins_report_only_header"`
	ExpectedCt     *ExpectedCtHeader `json:"expect_ct_header"`
}

type HstsHeader struct {
	Preload           bool `json:"preload"`
	IncludeSubdomains bool `json:"include_subdomains"`
	MaxAge            *int `json:"max_age"`
}

type HpkpHeader struct {
	Sha256Pins        []string `json:"sha256_pins"`
	IncludeSubdomains bool     `json:"include_subdomains"`
	MaxAge            *int     `json:"max_age"`
	ReportUri         *string  `json:"report_uri"`
	ReportTo          *string  `json:"report_to"`
}

type ExpectedCtHeader struct {
	Enforce   bool    `json:"enforce"`
	MaxAge    *int    `json:"max_age"`
	ReportUri *string `json:"report_uri"`
}

// Helper struct, because SSLyze (or Cryptography to be more precise) converts the time into UTC and removes the time
// zone information. Therefore golang can no longer parse the input automatically..
const timeFormat = "2006-01-02T15:04:05"

type UtcTime struct {
	String string
	Time   time.Time
}

func (ut *UtcTime) UnmarshalJSON(data []byte) error {
	t, errParse := time.Parse(timeFormat, strings.Trim(string(data), `"`))
	if errParse != nil {
		return errParse
	}

	ut.String = string(data)
	ut.Time = t
	return nil
}

func (ut *UtcTime) MarshalJSON() ([]byte, error) {
	stamp := fmt.Sprintf("\"%s\"", ut.Time.Format(timeFormat))
	return []byte(stamp), nil
}

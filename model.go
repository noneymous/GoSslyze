package gosslyze

type HostResult struct {
	Targets        []Target      `json:"accepted_targets"`
	InvalidTargets []interface{} `json:"invalid_targets"`
	Url            string        `json:"sslyze_url"`
	Version        string        `json:"sslyze_version"`
	TotalScanTime  string        `json:"total_scan_time"`
}

type Target struct {
	CommandResults CommandResults `json:"commands_results"`
	ServerInfo     ServerInfo     `json:"server_info"`
}

type ServerInfo struct {
	ClientAuthCred        *string     `json:"client_auth_credentials"`
	ClientAuthReq         string      `json:"client_auth_requirement"`
	HighVer               interface{} `json:"highest_ssl_version_supported"`
	Hostname              string      `json:"hostname"`
	HttpTunnelingSettings interface{} `json:"http_tunneling_settings"`
	Ip                    string      `json:"ip_address"`
	SupportedCipher       string      `json:"openssl_cipher_string_supported"`
	Port                  int         `json:"port"`
	Sni                   string      `json:"tls_server_name_indication"`
	WrappedProtocol       string      `json:"tls_wrapped_protocol"`
	XmppToHostname        interface{} `json:"xmpp_to_hostname"`
}

type CommandResults struct {
	CertInfo CertInfo `json:"certinfo"`

	Compression struct {
		CompressionName *string `json:"compression_name"`
	} `json:"compression"`

	EarlyData struct {
		IsSupported bool `json:"is_early_data_supported"`
	} `json:"early_data"`

	Fallback struct {
		FallbackScsv bool `json:"supports_fallback_scsv"`
	} `json:"fallback"`

	Heartbleed struct {
		IsVulnerable bool `json:"is_vulnerable_to_heartbleed"`
	} `json:"heartbleed"`

	OpensslCcs struct {
		IsVulnerable bool `json:"is_vulnerable_to_ccs_injection"`
	} `json:"openssl_ccs"`

	Renegotiation struct {
		AcceptsClientRenegotiation  bool `json:"accepts_client_renegotiation"`
		SupportsSecureRenegotiation bool `json:"supports_secure_renegotiation"`
	} `json:"reneg"`

	Resum struct {
		RateResult struct {
			ServerInfo   ServerInfo  `json:"server_info"`
			ScanCommand  interface{} `json:"scan_command"`
			NbAttempted  int         `json:"attempted_resumptions_nb"` // Should be 100
			NbSuccessful int         `json:"successful_resumptions_nb"`
			NbFailed     int         `json:"failed_resumptions_nb"`
			ErroredList  []string    `json:"errored_resumptions_list"`
		} `json:"_rate_result"`
		NbAttempted        int      `json:"attempted_resumptions_nb"`
		NbSuccessful       int      `json:"successful_resumptions_nb"`
		NbFailed           int      `json:"failed_resumptions_nb"`
		ErroredList        []string `json:"errored_resumptions_list"`
		IsTicketSupported  bool     `json:"is_ticket_resumption_supported"`
		TicketFailedReason *string  `json:"ticket_resumption_failed_reason"`
		TicketError        *string  `json:"ticket_resumption_exception"`
	} `json:"resum"`

	Robot struct {
		RobotEnum string `json:"robot_result_enum"`
	} `json:"robot"`

	SslV3   Protocol `json:"sslv3"`
	SslV2   Protocol `json:"sslv2"`
	TlsV1   Protocol `json:"tlsv1"`
	TlsV1_1 Protocol `json:"tlsv1_1"`
	TlsV1_2 Protocol `json:"tlsv1_2"`
	TlsV1_3 Protocol `json:"tlsv1_3"`
}

type Protocol struct {
	AcceptedCipherList []Cipher `json:"accepted_cipher_list"`
	ErrorCipherList    []Cipher `json:"errored_cipher_list"`
	PreferredCipher    *Cipher  `json:"preferred_cipher"`
	RejectedCipherList []Cipher `json:"rejected_cipher_list"`
}

type Cipher struct {
	IsAnonymous           bool   `json:"is_anonymous"`
	KeySize               int    `json:"key_size"`
	OpenSslName           string `json:"openssl_name"`
	PostHandshakeResponse string `json:"post_handshake_response"`
	SslVer                string `json:"ssl_version"`
}

type CertInfo struct {
	StapleExtension       bool             `json:"leaf_certificate_has_must_staple_extension"`
	IsLeafEv              bool             `json:"leaf_certificate_is_ev"`
	SctsCount             int              `json:"leaf_certificate_signed_certificate_timestamps_count"`
	MatchHostname         bool             `json:"leaf_certificate_subject_matches_hostname"`
	OcspResponse          interface{}      `json:"ocsp_response"`
	OcspIsTrusted         interface{}      `json:"ocsp_response_is_trusted"`
	OcspResponseStatus    interface{}      `json:"ocsp_response_status"`
	PathValidationErrList []interface{}    `json:"path_validation_error_list"`
	PathValidationList    []CertPathResult `json:"path_validation_result_list"`
	CertificateChain      []Certificate    `json:"received_certificate_chain"`
	HasAnchor             bool             `json:"received_chain_contains_anchor_certificate"`
	IsChainValid          bool             `json:"received_chain_has_valid_order"`
	VerifiedCertChain     []Certificate    `json:"verified_certificate_chain"`
	SymantecDistrust      bool             `json:"verified_chain_has_legacy_symantec_anchor"`
	HasSha1               bool             `json:"verified_chain_has_sha1_signature"`
}

type Certificate struct {
	Pem            string      `json:"as_pem"`
	HpkpPin        string      `json:"hpkp_pin"`
	Issuer         string      `json:"issuer"`
	NotAfter       string      `json:"notAfter"`
	NotBefore      string      `json:"notBefore"`
	PublicKey      PublicKey   `json:"publicKey"`
	Serial         string      `json:"serialNumber"`
	SignatureAlg   string      `json:"signatureAlgorithm"`
	Subject        string      `json:"subject"`
	SubjectAltName SubjAltName `json:"subjectAlternativeName"`
}

type PublicKey struct {
	Algorithm string `json:"algorithm"`
	Curve     string `json:"curve"`
	Exponent  string `json:"exponent"`
	Size      string `json:"size"`
}

type SubjAltName struct {
	Dns []string `json:"DNS"`
}

type CertPathResult struct {
	IsTrusted    bool       `json:"is_certificate_trusted"`
	TrustStore   TrustStore `json:"trust_store"`
	VerifyString string     `json:"verify_string"`
}

type TrustStore struct {
	EvOids  []string `json:"ev_oids"`
	Name    string   `json:"name"`
	Path    string   `json:"path"`
	Version string   `json:"version"`
}

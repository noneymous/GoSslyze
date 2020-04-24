package gosslyze

// Constants to compare enums and strings against

const (
	CommandErrorReasonBugInSslyze             = "BUG_IN_SSLYZE"
	CommandErrorReasonClientCertificateNeeded = "CLIENT_CERTIFICATE_NEEDED "
	CommandErrorReasonConnectivityIssue       = "CONNECTIVITY_ISSUE "
	CommandErrorReasonWrongUsage              = "WRONG_USAGE "
)

const (
	Ssl2  = "SSL_2_0"
	Ssl3  = "SSL_3_0"
	Tls10 = "TLS_1_0"
	Tls11 = "TLS_1_1"
	Tls12 = "TLS_1_2"
	Tls13 = "TLS_1_3"
)

const (
	ClientAuthDisabled = "DISABLED"
	ClientAuthOptional = "OPTIONAL"
	ClientAuthRequired = "REQUIRED"
)

const (
	ClientAuthKeyTypePem  = "PEM"
	ClientAuthKeyTypeAsn1 = "ASN1"
)

const (
	EphemeralKeyTypeDH     = 28
	EphemeralKeyTypeEC     = 408
	EphemeralKeyTypeX25519 = 1034
	EphemeralKeyTypeX448   = 1035
)

const (
	// RFC4492 (now deprecated)
	EphemeralKeyCurveTypeSect163K1 = 721
	EphemeralKeyCurveTypeSect163R1 = 722
	EphemeralKeyCurveTypeSect163R2 = 723
	EphemeralKeyCurveTypeSect193R1 = 724
	EphemeralKeyCurveTypeSect193R2 = 725
	EphemeralKeyCurveTypeSect233K1 = 726
	EphemeralKeyCurveTypeSect233R1 = 727
	EphemeralKeyCurveTypeSect239K1 = 728
	EphemeralKeyCurveTypeSect283K1 = 729
	EphemeralKeyCurveTypeSect283R1 = 730
	EphemeralKeyCurveTypeSect409K1 = 731
	EphemeralKeyCurveTypeSect409R1 = 732
	EphemeralKeyCurveTypeSect571K1 = 733
	EphemeralKeyCurveTypeSect571R1 = 734
	EphemeralKeyCurveTypeSecp160K1 = 708
	EphemeralKeyCurveTypeSecp160R1 = 709
	EphemeralKeyCurveTypeSecp160R2 = 710
	EphemeralKeyCurveTypeSecp192K1 = 711
	EphemeralKeyCurveTypeSecp224K1 = 712
	EphemeralKeyCurveTypeSecp224R1 = 713
	EphemeralKeyCurveTypeSecp256K1 = 714

	// RFC8422 (current)
	EphemeralKeyCurveTypeSecp192R1  = 409
	EphemeralKeyCurveTypePrime192V1 = 409 // Intentional duplicate of SECP192R1
	EphemeralKeyCurveTypeSecp256R1  = 415
	EphemeralKeyCurveTypePrime256V1 = 415 // Intentional duplicate of SECP256R1
	EphemeralKeyCurveTypeSecp384R1  = 715
	EphemeralKeyCurveTypeSecp521R1  = 716
	EphemeralKeyCurveTypeX25519     = 1034
	EphemeralKeyCurveTypeX448       = 1035
)

const (
	TicketResumptionSuccess            = "SUCCEEDED"
	TicketResumptionTicketNotAssigned  = "FAILED_TICKET_NOT_ASSIGNED"
	TicketResumptionTicketIgnored      = "FAILED_TICKED_IGNORED"
	TicketResumptionOnlyTls13Supported = "FAILED_ONLY_TLS_1_3_SUPPORTED"
)

const (
	RobotVulnerableWeakOracle         = "VULNERABLE_WEAK_ORACLE"
	RobotVulnerableStrongOracle       = "VULNERABLE_STRONG_ORACLE"
	RobotNotVulnerableNoOracle        = "NOT_VULNERABLE_NO_ORACLE"
	RobotNotVulnerableRsaNotSupported = "NOT_VULNERABLE_RSA_NOT_SUPPORTED"
	RobotUnknownInconsistentResults   = "UNKNOWN_INCONSISTENT_RESULTS"
)

const (
	OcspRespStatusSuccessful        = "SUCCESSFUL"
	OcspRespStatusMalformedRequest  = "MALFORMED_REQUEST"
	OcspRespStatusInternalError     = "INTERNAL_ERROR"
	OcspRespStatusTryLater          = "TRY_LATER"
	OcspRespStatusSignatureRequired = "SIG_REQUIRED"
	OcspRespStatusUnauthorized      = "UNAUTHORIZED"
)

const (
	OpportunisticTlsSmtp       = "SMTP"
	OpportunisticTlsXmpp       = "XMPP"
	OpportunisticTlsXMppServer = "XMPP_SERVER"
	OpportunisticTlsFtp        = "FTP"
	OpportunisticTlsPop3       = "POP3"
	OpportunisticTlsLdap       = "LDAP"
	OpportunisticTlsImap       = "IMAP"
	OpportunisticTlsRdp        = "RDP"
	OpportunisticTlsPostgres   = "POSTGRES"
)

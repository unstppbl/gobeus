//go:build windows

package lsa

type TicketFlags uint32

type (
	BOOL          uint32
	BOOLEAN       byte
	BYTE          byte
	DWORD         uint32
	DWORD64       uint64
	HANDLE        uintptr
	HLOCAL        uintptr
	LARGE_INTEGER int64
	LONG          int32
	LPVOID        uintptr
	SIZE_T        uintptr
	UINT          uint32
	ULONG_PTR     uintptr
	ULONGLONG     uint64
	WORD          uint16
)

const (
	reserved          = 2147483648
	forwardable       = 0x40000000
	forwarded         = 0x20000000
	proxiable         = 0x10000000
	proxy             = 0x08000000
	may_postdate      = 0x04000000
	postdated         = 0x02000000
	invalid           = 0x01000000
	renewable         = 0x00800000
	initial           = 0x00400000
	pre_authent       = 0x00200000
	hw_authent        = 0x00100000
	ok_as_delegate    = 0x00040000
	anonymous         = 0x00020000
	name_canonicalize = 0x00010000
	//cname_in_pa_data = 0x00040000,
	enc_pa_rep = 0x00010000
	reserved1  = 0x00000001
	empty      = 0x00000000
	// TODO: constrained delegation?
)

type KERB_QUERY_TKT_CACHE_REQUEST struct {
	MessageType KERB_PROTOCOL_MESSAGE_TYPE
	LogonId     LUID
}

type KERB_QUERY_TKT_CACHE_EX_RESPONSE struct {
	MessageType    int32
	CountOfTickets int32
	// Tickets        []KERB_TICKET_CACHE_INFO_EX
	Tickets uintptr
}

type KERB_TICKET_CACHE_INFO_EX struct {
	ClientName     LSA_UNICODE_STRING
	ClientRealm    LSA_UNICODE_STRING
	ServerName     LSA_UNICODE_STRING
	ServerRealm    LSA_UNICODE_STRING
	StartTime      int64
	EndTime        int64
	RenewTime      int64
	EncryptionType int32
	TicketFlags    uint32
}

type KERB_TICKET_CACHE_INFO_EX_OUT struct {
	ClientName     string
	ClientRealm    string
	ServerName     string
	ServerRealm    string
	StartTime      int64
	EndTime        int64
	RenewTime      int64
	EncryptionType int32
	TicketFlags    uint32
}

type KERB_PROTOCOL_MESSAGE_TYPE uint32

const (
	KerbDebugRequestMessage                 = 0
	KerbQueryTicketCacheMessage             = 1
	KerbChangeMachinePasswordMessage        = 2
	KerbVerifyPacMessage                    = 3
	KerbRetrieveTicketMessage               = 4
	KerbUpdateAddressesMessage              = 5
	KerbPurgeTicketCacheMessage             = 6
	KerbChangePasswordMessage               = 7
	KerbRetrieveEncodedTicketMessage        = 8
	KerbDecryptDataMessage                  = 9
	KerbAddBindingCacheEntryMessage         = 10
	KerbSetPasswordMessage                  = 11
	KerbSetPasswordExMessage                = 12
	KerbVerifyCredentialsMessage            = 13
	KerbQueryTicketCacheExMessage           = 14
	KerbPurgeTicketCacheExMessage           = 15
	KerbRefreshSmartcardCredentialsMessage  = 16
	KerbAddExtraCredentialsMessage          = 17
	KerbQuerySupplementalCredentialsMessage = 18
	KerbTransferCredentialsMessage          = 19
	KerbQueryTicketCacheEx2Message          = 20
	// KerbSubmitTicketMessage is the message type for submitting a ticket (pass-the-ticket)
	// as defined in the undocumented KERB_SUBMIT_TKT_REQUEST structure.
	KerbSubmitTicketMessage                = 21
	KerbAddExtraCredentialsExMessage       = 22
	KerbQueryKdcProxyCacheMessage          = 23
	KerbPurgeKdcProxyCacheMessage          = 24
	KerbQueryTicketCacheEx3Message         = 25
	KerbCleanupMachinePkinitCredsMessage   = 26
	KerbAddBindingCacheEntryExMessage      = 27
	KerbQueryBindingCacheMessage           = 28
	KerbPurgeBindingCacheMessage           = 29
	KerbQueryDomainExtendedPoliciesMessage = 30
	KerbQueryS4U2ProxyCacheMessage         = 31
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type KERB_RETRIEVE_TKT_RESPONSE struct {
	Ticket *KERB_EXTERNAL_TICKET
}

type KERB_EXTERNAL_TICKET struct {
	ServiceName         uintptr
	TargetName          uintptr
	ClientName          uintptr
	DomainName          LSA_UNICODE_STRING
	TargetDomainName    LSA_UNICODE_STRING
	AltTargetDomainName LSA_UNICODE_STRING
	SessionKey          KERB_CRYPTO_KEY
	TicketFlags         uint32
	Flags               uint32
	KeyExpirationTime   int64
	StartTime           int64
	EndTime             int64
	RenewUntil          int64
	TimeSkew            int64
	EncodedTicketSize   int32
	EncodedTicket       uintptr
}

type NOPE_KERB_EXTERNAL_TICKET struct {
	ServiceName         *KERB_EXTERNAL_NAME
	TargetName          *KERB_EXTERNAL_NAME
	ClientName          *KERB_EXTERNAL_NAME
	DomainName          LSA_UNICODE_STRING
	TargetDomainName    LSA_UNICODE_STRING
	AltTargetDomainName LSA_UNICODE_STRING
	SessionKey          KERB_CRYPTO_KEY
	TicketFlags         uint32
	Flags               uint32
	KeyExpirationTime   uint64
	StartTime           uint64
	EndTime             uint64
	RenewUntil          uint64
	TimeSkew            uint64
	EncodedTicketSize   uint32
	EncodedTicket       uintptr
}

type KERB_EXTERNAL_NAME struct {
	NameType  int32
	NameCount uint32
	Names     uintptr
}

type KERB_CRYPTO_KEY struct {
	KeyType int32
	Length  uint32
	Value   uintptr
}

type KERB_CRYPTO_KEY32 struct {
	KeyType uint32
	Length  uint32
	// In the C definition, this is usually a pointer: PUCHAR Value;
	// For 32-bit, you might use uint32; for 64-bit, you likely need uintptr.
	Value uint32
}

// KERB_SUBMIT_TKT_REQUEST is the structure used to pass a ticket to LSA.
type KERB_SUBMIT_TKT_REQUEST struct {
	MessageType    KERB_PROTOCOL_MESSAGE_TYPE // Must be KerbSubmitTicketMessage
	LogonId        LUID                       // Use {0,0} for the current session
	Flags          uint32                     // Usually 0
	Key            KERB_CRYPTO_KEY32          // Typically zeroed out
	KerbCredSize   uint32                     // Size of the ticket blob
	KerbCredOffset uint32                     // Offset to the start of the ticket blob
}

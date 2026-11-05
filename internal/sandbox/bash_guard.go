package sandbox

import (
	"regexp"
	"strings"
)

var (
	reRmRfRoot       = regexp.MustCompile(`(?i)\brm\s+(-[a-z]*r[a-z]*f|--force|-[a-z]*f[a-z]*r)\s+(/|~|\*|/\*|\$HOME)(?:\s+|$)`)
	reForkBomb       = regexp.MustCompile(`:\(\)\s*\{\s*:\|:&\s*\};:`)
	reExfilNetcat    = regexp.MustCompile(`(?i)\bnc\s+.*(-e|/bin/sh|/bin/bash)\b`)
	reDevTcp         = regexp.MustCompile(`/dev/(tcp|udp)/[0-9a-zA-Z._-]+/\d+`)
	reCurlExfil      = regexp.MustCompile(`(?i)\bcurl\s+.*(-d\s*@|-F\s*.*=@[^/]*(/etc/|id_rsa|\.env))\b`)
	reSensitiveFiles = regexp.MustCompile(`(?i)(/etc/shadow|\.ssh/id_rsa|\.aws/credentials|id_ed25519)`)
	reSudo           = regexp.MustCompile(`(?i)\b(sudo\s+|su\s+-)`)
	reDiskWipe       = regexp.MustCompile(`(?i)\b(mkfs|dd\s+if=/dev/(zero|urandom)\s+of=/dev/)\b`)
)

type BashVerdict struct {
	IsDangerous bool   `json:"is_dangerous"`
	Reason      string `json:"reason,omitempty"`
}

func AnalyzeBash(cmd string) BashVerdict {
	clean := strings.TrimSpace(cmd)
	if clean == "" {
		return BashVerdict{IsDangerous: false}
	}

	if reRmRfRoot.MatchString(clean) {
		return BashVerdict{
			IsDangerous: true,
			Reason:      "Destructive root/home recursive deletion (rm -rf) blocked",
		}
	}

	if reForkBomb.MatchString(clean) {
		return BashVerdict{
			IsDangerous: true,
			Reason:      "Fork bomb pattern detected and blocked",
		}
	}

	if reDevTcp.MatchString(clean) {
		return BashVerdict{
			IsDangerous: true,
			Reason:      "Interactive reverse shell via /dev/tcp or /dev/udp blocked",
		}
	}

	if reExfilNetcat.MatchString(clean) {
		return BashVerdict{
			IsDangerous: true,
			Reason:      "Netcat shell execution / reverse connect blocked",
		}
	}

	if reCurlExfil.MatchString(clean) {
		return BashVerdict{
			IsDangerous: true,
			Reason:      "Outbound data exfiltration of sensitive files via curl blocked",
		}
	}

	if reSensitiveFiles.MatchString(clean) && (strings.Contains(clean, "cat ") || strings.Contains(clean, "less ") || strings.Contains(clean, "curl ") || strings.Contains(clean, "scp ")) {
		return BashVerdict{
			IsDangerous: true,
			Reason:      "Direct read/transfer of SSH private key or shadow password file blocked",
		}
	}

	if reDiskWipe.MatchString(clean) {
		return BashVerdict{
			IsDangerous: true,
			Reason:      "Disk format / block device wiping command blocked",
		}
	}

	if reSudo.MatchString(clean) {
		return BashVerdict{
			IsDangerous: true,
			Reason:      "Privilege escalation via sudo/su blocked by sandbox",
		}
	}

	return BashVerdict{IsDangerous: false}
}

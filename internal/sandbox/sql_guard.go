package sandbox

import (
	"regexp"
	"strings"
)

var (
	reDrop        = regexp.MustCompile(`(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA|VIEW|INDEX)\b`)
	reTruncate    = regexp.MustCompile(`(?i)\bTRUNCATE\s+(TABLE)?\b`)
	reAlter       = regexp.MustCompile(`(?i)\bALTER\s+(TABLE|DATABASE)\b`)
	reExecCmd     = regexp.MustCompile(`(?i)\b(xp_cmdshell|sp_executesql|exec\s*\(|execute\s*\()\b`)
	reDelete      = regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`)
	reUpdate      = regexp.MustCompile(`(?i)\bUPDATE\s+`)
	reWhere       = regexp.MustCompile(`(?i)\bWHERE\b`)
	reSelect      = regexp.MustCompile(`(?i)^\s*SELECT\b`)
	reInsert      = regexp.MustCompile(`(?i)^\s*INSERT\s+INTO\b`)
	reInformation = regexp.MustCompile(`(?i)\binformation_schema\b`)
)

type SQLVerdict struct {
	IsDestructive bool   `json:"is_destructive"`
	Category      string `json:"category"` // READ, WRITE, DESTRUCTIVE, DANGEROUS
	Reason        string `json:"reason,omitempty"`
}

func AnalyzeSQL(query string) SQLVerdict {
	clean := strings.TrimSpace(query)
	if clean == "" {
		return SQLVerdict{IsDestructive: false, Category: "EMPTY"}
	}

	if reDrop.MatchString(clean) {
		return SQLVerdict{
			IsDestructive: true,
			Category:      "DESTRUCTIVE",
			Reason:        "DROP statements are deterministically blocked by Aegis sandbox",
		}
	}

	if reTruncate.MatchString(clean) {
		return SQLVerdict{
			IsDestructive: true,
			Category:      "DESTRUCTIVE",
			Reason:        "TRUNCATE statements are deterministically blocked by Aegis sandbox",
		}
	}

	if reAlter.MatchString(clean) {
		return SQLVerdict{
			IsDestructive: true,
			Category:      "DESTRUCTIVE",
			Reason:        "Schema alteration (ALTER TABLE/DATABASE) blocked",
		}
	}

	if reExecCmd.MatchString(clean) {
		return SQLVerdict{
			IsDestructive: true,
			Category:      "DANGEROUS",
			Reason:        "Stored procedure/shell execution in SQL blocked",
		}
	}

	if reDelete.MatchString(clean) {
		if !reWhere.MatchString(clean) {
			return SQLVerdict{
				IsDestructive: true,
				Category:      "DESTRUCTIVE",
				Reason:        "Unbounded DELETE without a WHERE clause is blocked",
			}
		}
		return SQLVerdict{
			IsDestructive: false,
			Category:      "WRITE",
			Reason:        "Scoped DELETE with WHERE clause",
		}
	}

	if reUpdate.MatchString(clean) {
		if !reWhere.MatchString(clean) {
			return SQLVerdict{
				IsDestructive: true,
				Category:      "DESTRUCTIVE",
				Reason:        "Unbounded UPDATE without a WHERE clause is blocked",
			}
		}
		return SQLVerdict{
			IsDestructive: false,
			Category:      "WRITE",
			Reason:        "Scoped UPDATE with WHERE clause",
		}
	}

	if reInsert.MatchString(clean) {
		return SQLVerdict{
			IsDestructive: false,
			Category:      "WRITE",
			Reason:        "INSERT statement allowed",
		}
	}

	if reSelect.MatchString(clean) {
		if reInformation.MatchString(clean) {
			return SQLVerdict{
				IsDestructive: false,
				Category:      "SCHEMA_READ",
				Reason:        "Metadata schema read",
			}
		}
		return SQLVerdict{
			IsDestructive: false,
			Category:      "READ",
			Reason:        "Safe SELECT query",
		}
	}

	return SQLVerdict{
		IsDestructive: false,
		Category:      "OTHER",
	}
}

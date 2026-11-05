package sandbox

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	reSSN        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	reCreditCard = regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{4}\b|\b\d{15,16}\b`)
	reSecretKey  = regexp.MustCompile(`\b(sk_[a-zA-Z0-9_]{24,}|ghp_[0-9a-zA-Z]{36}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9a-zA-Z]{10,48})\b`)
	reEnvSecret  = regexp.MustCompile(`(?i)\b([A-Z_0-9]*(?:API_KEY|SECRET|PASSWORD|PRIVATE_KEY))\s*[:=]\s*["']?([^\s"']+)["']?`)
)

func isValidLuhn(number string) bool {
	clean := strings.ReplaceAll(strings.ReplaceAll(number, "-", ""), " ", "")
	if len(clean) < 13 || len(clean) > 19 {
		return false
	}

	sum := 0
	alternate := false
	for i := len(clean) - 1; i >= 0; i-- {
		n, err := strconv.Atoi(string(clean[i]))
		if err != nil {
			return false
		}
		if alternate {
			n *= 2
			if n > 9 {
				n = (n % 10) + 1
			}
		}
		sum += n
		alternate = !alternate
	}
	return sum%10 == 0
}

func RedactPII(input string) string {
	if input == "" {
		return input
	}

	// 1. Redact SSN
	out := reSSN.ReplaceAllString(input, "[REDACTED_SSN]")

	// 2. Redact Known Secret Keys
	out = reSecretKey.ReplaceAllString(out, "[REDACTED_SECRET_KEY]")

	// 3. Redact Env formatted secrets
	out = reEnvSecret.ReplaceAllString(out, "$1=[REDACTED_SECRET]")

	// 4. Redact Credit Cards with Luhn check
	out = reCreditCard.ReplaceAllStringFunc(out, func(match string) string {
		if isValidLuhn(match) {
			return "[REDACTED_CREDIT_CARD]"
		}
		return match
	})

	return out
}

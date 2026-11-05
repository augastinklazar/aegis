package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMerkleAudit_TamperEvidence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aegis_audit_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test_audit.db")
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	logger, err := NewLogger(db)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Log 3 sequential actions
	e1, err := logger.Log("agent_1", "t1", "stripe", "refund", []byte(`{"amount":100}`), "ALLOWED", "", "")
	if err != nil || e1.Seq != 1 || e1.PrevHash != GenesisHash {
		t.Fatalf("first entry invalid: %+v", e1)
	}

	e2, err := logger.Log("agent_1", "t1", "stripe", "refund", []byte(`{"amount":5000}`), "ESCALATED_APPROVED", "admin", "sig_xyz")
	if err != nil || e2.Seq != 2 || e2.PrevHash != e1.RecordHash {
		t.Fatalf("second entry prev_hash chaining failed: %+v", e2)
	}

	e3, err := logger.Log("agent_2", "t2", "bash", "execute", []byte(`{"cmd":"ls"}`), "ALLOWED", "", "")
	if err != nil || e3.Seq != 3 || e3.PrevHash != e2.RecordHash {
		t.Fatalf("third entry prev_hash chaining failed: %+v", e3)
	}

	// 2. Verify legitimate chain
	report, err := logger.VerifyChain()
	if err != nil || !report.Valid || report.TotalBlocks != 3 {
		t.Fatalf("expected valid chain of 3 blocks, got: %+v (err: %v)", report, err)
	}

	// 3. Simulate malicious tampering: adversary attempts to alter sequence 2 payload in SQLite
	_, err = db.Exec(`UPDATE audit_log SET raw_payload = '{"amount":10}' WHERE seq = 2`)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Verify tampering is deterministically caught by Merkle chain
	reportTampered, err := logger.VerifyChain()
	if err != nil {
		t.Fatal(err)
	}
	if reportTampered.Valid {
		t.Fatal("expected chain verification to FAIL after data tamper, but it passed!")
	}
	if reportTampered.BrokenSeq != 2 {
		t.Fatalf("expected broken sequence 2, got %d", reportTampered.BrokenSeq)
	}
}

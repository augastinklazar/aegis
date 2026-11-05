package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/augastinklazar/aegis/internal/audit"
	"github.com/augastinklazar/aegis/internal/broker"
	"github.com/augastinklazar/aegis/internal/config"
	"github.com/augastinklazar/aegis/internal/hitl"
	"github.com/augastinklazar/aegis/internal/hitl/notifiers"
	"github.com/augastinklazar/aegis/internal/proxy"
	"github.com/augastinklazar/aegis/internal/sandbox"
	"github.com/augastinklazar/aegis/internal/vault"
	"github.com/augastinklazar/aegis/web"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "serve":
		runServe(os.Args[2:])
	case "wrap-mcp":
		runWrapMCP(os.Args[2:])
	case "init":
		runInit(os.Args[2:])
	case "vault":
		runVault(os.Args[2:])
	case "token":
		runToken(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	banner := `
   _____  ______ _____ _____ _____ 
  / _ \ \/ / ___|_   _/ ____/ ____|
 / /_\ \  /| |  _ | || (___| (___  
 |  _  |/  \| |_| || | \___ \\___ \ 
 |_| |_/_/\_\\____|___/____/|____/ 
 Autonomous Agent Zero-Trust Gateway
`
	fmt.Println(banner)
	fmt.Println("Usage: aegis <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  serve       Start the Aegis gateway daemon (proxy, HITL, vault, UI)")
	fmt.Println("  wrap-mcp    Wrap a local MCP server over stdio with policy firewall")
	fmt.Println("  init        Initialize local vault database and master keys")
	fmt.Println("  vault       Manage encrypted upstream API keys and credentials")
	fmt.Println("  token       Issue and inspect task-scoped phantom tokens")
	fmt.Println("  verify      Verify cryptographic Merkle hash chain integrity")
	fmt.Println("\nRun 'aegis <command> --help' for details on specific commands.")
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.String("port", "", "HTTP listen port (default: 8080 or AEGIS_PORT)")
	dbPath := fs.String("db", "", "SQLite DB path (default: aegis.db or AEGIS_DB_PATH)")
	policiesDir := fs.String("policies", "", "Policies directory (default: policies)")
	fs.Parse(args)

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed loading config: %v", err)
	}

	if *port != "" {
		cfg.Port = *port
		cfg.BaseURL = "http://localhost:" + *port
	}
	if *dbPath != "" {
		cfg.DBPath = *dbPath
	}
	if *policiesDir != "" {
		cfg.PoliciesDir = *policiesDir
	}

	// 1. Vault
	v, err := vault.NewVault(cfg.DBPath, cfg.VaultKey)
	if err != nil {
		log.Fatalf("init vault failed: %v", err)
	}
	defer v.Close()

	// 2. State Counter & Audit Logger
	sc, err := sandbox.NewStateCounter(v.DB())
	if err != nil {
		log.Fatalf("init state counter failed: %v", err)
	}

	al, err := audit.NewLogger(v.DB())
	if err != nil {
		log.Fatalf("init audit logger failed: %v", err)
	}

	// 3. CEL Sandbox Policy Engine
	sb, err := sandbox.NewCELEngine(sc)
	if err != nil {
		log.Fatalf("init cel sandbox failed: %v", err)
	}

	// Load policies: load local dir and presets
	sb.LoadPoliciesFromDir(cfg.PoliciesDir)
	sb.LoadPoliciesFromDir(filepath.Join(cfg.PoliciesDir, "presets"))

	// 4. Broker & Phantom Manager
	pm, err := broker.NewPhantomManager(v.DB())
	if err != nil {
		log.Fatalf("init phantom manager failed: %v", err)
	}

	ar, err := broker.NewAgentRegistry(v.DB())
	if err != nil {
		log.Fatalf("init agent registry failed: %v", err)
	}

	brk := broker.NewBroker(pm, ar, cfg.JWTSecret)

	// 5. HITL Park Manager & Dispatcher
	park, err := hitl.NewParkManager(v.DB())
	if err != nil {
		log.Fatalf("init park manager failed: %v", err)
	}

	disp := notifiers.NewDispatcher(cfg.TelegramBot, cfg.TelegramChat, cfg.DiscordHook, cfg.SlackHook)
	passkeyMgr, err := hitl.NewPasskeyManager(v.DB(), cfg.BaseURL, cfg.JWTSecret)
	if err != nil {
		log.Printf("webauthn passkey note: %v", err)
	}

	// 6. Upstream Refresh Daemon
	refresher := broker.NewRefresherDaemon(v, 60*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	refresher.Start(ctx)

	// 7. Proxies
	httpGateway := proxy.NewGateway(v, pm, sb, sc, park, disp, al, cfg.BaseURL)
	mcpSSEProxy := proxy.NewMCPSSEProxy(sb, sc, park, disp, al, cfg.BaseURL)

	// HTTP Router
	mux := http.NewServeMux()

	// Embedded Web UI
	mux.Handle("/", web.AssetHandler())

	// Token Exchange (RFC 8693)
	mux.HandleFunc("POST /v1/oauth/token", brk.ServeHTTP)

	// Agent Registration
	mux.HandleFunc("POST /v1/agents/register", func(w http.ResponseWriter, r *http.Request) {
		var m broker.AgentManifest
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
			return
		}
		if err := ar.Register(&m); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(m)
	})

	mux.HandleFunc("GET /v1/agents", func(w http.ResponseWriter, r *http.Request) {
		agents, err := ar.List()
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agents)
	})

	// Reverse Proxy Gateway
	mux.Handle("/proxy/", httpGateway)

	// MCP SSE Proxy
	mux.Handle("/mcp/", mcpSSEProxy)

	// HITL Endpoints
	mux.HandleFunc("GET /v1/hitl/pending", func(w http.ResponseWriter, r *http.Request) {
		pending := park.GetPending()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pending)
	})

	mux.HandleFunc("GET /v1/hitl/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		req, err := park.GetRequest(id)
		if err != nil {
			http.Error(w, `{"error":"request_not_found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(req)
	})

	mux.HandleFunc("POST /v1/hitl/requests/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var body struct {
			Approver  string `json:"approver"`
			Signature string `json:"signature"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Approver == "" {
			body.Approver = "admin@aegis"
		}
		if body.Signature == "" && passkeyMgr != nil {
			body.Signature = passkeyMgr.GenerateHMACSignature(id, "APPROVED", body.Approver)
		}

		if err := park.Resolve(id, true, body.Approver, body.Signature, ""); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "approved", "request_id": id})
	})

	mux.HandleFunc("POST /v1/hitl/requests/{id}/deny", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var body struct {
			Approver string `json:"approver"`
			Reason   string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Reason == "" {
			body.Reason = "Rejected by human operator"
		}
		if err := park.Resolve(id, false, body.Approver, "", body.Reason); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "denied", "request_id": id})
	})

	// Audit Trail Endpoints
	mux.HandleFunc("GET /v1/audit", func(w http.ResponseWriter, r *http.Request) {
		entries, err := al.GetRecent(50)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	})

	mux.HandleFunc("GET /v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		rep, err := al.VerifyChain()
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rep)
	})

	// Vault Management Endpoints
	mux.HandleFunc("GET /v1/vault/services", func(w http.ResponseWriter, r *http.Request) {
		services, err := v.ListServices()
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"services": services})
	})

	mux.HandleFunc("POST /v1/vault/secrets", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ServiceID string `json:"service_id"`
			Secret    string `json:"secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
			return
		}
		if err := v.SetSecret(body.ServiceID, body.Secret); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "saved", "service_id": body.ServiceID})
	})

	// Policy Simulator
	mux.HandleFunc("POST /v1/sandbox/simulate", func(w http.ResponseWriter, r *http.Request) {
		var ctx sandbox.EvalContext
		if err := json.NewDecoder(r.Body).Decode(&ctx); err != nil {
			http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
			return
		}
		res, err := sb.Evaluate(&ctx)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	})

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: mux,
	}

	go func() {
		log.Printf("🛡️ Aegis Gateway live at %s", cfg.BaseURL)
		log.Printf("   ├─ Dashboard: %s/", cfg.BaseURL)
		log.Printf("   ├─ Token Exchange: POST %s/v1/oauth/token", cfg.BaseURL)
		log.Printf("   ├─ Proxy Boundary: %s/proxy/{service}/*", cfg.BaseURL)
		log.Printf("   └─ Audit Stream: %s/audit.html", cfg.BaseURL)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down Aegis Gateway...")
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sCancel()
	server.Shutdown(shutdownCtx)
}

func runWrapMCP(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: aegis wrap-mcp [--agent <id>] -- <command> [args...]")
		os.Exit(1)
	}

	agentID := "mcp-agent"
	var cmdArgs []string

	for i := 0; i < len(args); i++ {
		if args[i] == "--agent" && i+1 < len(args) {
			agentID = args[i+1]
			i++
		} else if args[i] == "--" {
			cmdArgs = args[i+1:]
			break
		} else {
			cmdArgs = args[i:]
			break
		}
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No command specified to wrap")
		os.Exit(1)
	}

	cfg, _ := config.LoadConfig()
	v, err := vault.NewVault(cfg.DBPath, cfg.VaultKey)
	if err != nil {
		log.Fatalf("wrap-mcp vault error: %v", err)
	}
	defer v.Close()

	sc, _ := sandbox.NewStateCounter(v.DB())
	al, _ := audit.NewLogger(v.DB())
	sb, _ := sandbox.NewCELEngine(sc)
	sb.LoadPoliciesFromDir(cfg.PoliciesDir)
	sb.LoadPoliciesFromDir(filepath.Join(cfg.PoliciesDir, "presets"))

	park, _ := hitl.NewParkManager(v.DB())
	disp := notifiers.NewDispatcher(cfg.TelegramBot, cfg.TelegramChat, cfg.DiscordHook, cfg.SlackHook)

	wrapper := proxy.NewMCPStdioWrapper(
		cmdArgs[0],
		cmdArgs[1:],
		sb,
		sc,
		park,
		disp,
		al,
		agentID,
		"mcp-session-"+time.Now().Format("150405"),
		cfg.BaseURL,
	)

	if err := wrapper.Run(); err != nil {
		os.Exit(1)
	}
}

func runInit(args []string) {
	dbPath := "aegis.db"
	if len(args) > 0 {
		dbPath = args[0]
	}

	key := config.GenerateKeyHex()
	fmt.Println("Initializing Aegis Gateway environment...")
	fmt.Printf("✓ Target Database: %s\n", dbPath)
	fmt.Printf("✓ Generated Master Vault Key: %s\n", key)
	fmt.Println("\nAdd to your environment:")
	fmt.Printf("  export AEGIS_VAULT_KEY=\"%s\"\n", key)
	fmt.Printf("  export AEGIS_DB_PATH=\"%s\"\n", dbPath)

	os.MkdirAll("policies/presets", 0755)
	fmt.Println("✓ Policy directory initialized at ./policies")
}

func runVault(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: aegis vault <set|get|list|delete> [args...]")
		return
	}

	cfg, _ := config.LoadConfig()
	v, err := vault.NewVault(cfg.DBPath, cfg.VaultKey)
	if err != nil {
		log.Fatalf("vault error: %v", err)
	}
	defer v.Close()

	sub := args[0]
	switch sub {
	case "set":
		if len(args) < 3 {
			fmt.Println("Usage: aegis vault set <service_id> <secret>")
			return
		}
		if err := v.SetSecret(args[1], args[2]); err != nil {
			log.Fatalf("set failed: %v", err)
		}
		fmt.Printf("✓ Secret stored securely for service '%s'\n", args[1])
	case "get":
		if len(args) < 2 {
			fmt.Println("Usage: aegis vault get <service_id>")
			return
		}
		sec, err := v.GetSecret(args[1])
		if err != nil {
			log.Fatalf("get failed: %v", err)
		}
		fmt.Println(sec)
	case "list":
		services, err := v.ListServices()
		if err != nil {
			log.Fatalf("list failed: %v", err)
		}
		fmt.Println("Vaulted Services:")
		for _, s := range services {
			fmt.Printf("  • %s\n", s)
		}
	case "delete":
		if len(args) < 2 {
			fmt.Println("Usage: aegis vault delete <service_id>")
			return
		}
		if err := v.DeleteSecret(args[1]); err != nil {
			log.Fatalf("delete failed: %v", err)
		}
		fmt.Printf("✓ Secret deleted for service '%s'\n", args[1])
	}
}

func runToken(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: aegis token issue --agent <id> --service <service> [--ttl <seconds>] [--max-calls <n>]")
		return
	}

	cfg, _ := config.LoadConfig()
	v, err := vault.NewVault(cfg.DBPath, cfg.VaultKey)
	if err != nil {
		log.Fatalf("token error: %v", err)
	}
	defer v.Close()

	pm, err := broker.NewPhantomManager(v.DB())
	if err != nil {
		log.Fatalf("phantom manager error: %v", err)
	}
	ar, _ := broker.NewAgentRegistry(v.DB())
	brk := broker.NewBroker(pm, ar, cfg.JWTSecret)

	fs := flag.NewFlagSet("token-issue", flag.ExitOnError)
	agentID := fs.String("agent", "cli-agent", "Agent ID")
	service := fs.String("service", "stripe_prod", "Target Service ID")
	sub := fs.String("sub", "human_operator", "Human Subject")
	ttl := fs.Int("ttl", 600, "TTL in seconds")
	calls := fs.Int("max-calls", 10, "Maximum allowed calls (0 for unlimited)")
	fs.Parse(args[1:])

	resp, err := brk.HandleTokenExchange(&broker.TokenExchangeRequest{
		GrantType:        broker.GrantTypeTokenExchange,
		SubjectToken:     *sub,
		SubjectTokenType: broker.TokenTypeJWT,
		ActorToken:       *agentID,
		Audience:         *service,
		TTLSeconds:       *ttl,
		MaxCalls:         *calls,
	})
	if err != nil {
		log.Fatalf("token exchange error: %v", err)
	}

	fmt.Println("✓ Task-Scoped Phantom Token Issued:")
	fmt.Printf("  Token:     %s\n", resp.AccessToken)
	fmt.Printf("  Service:   %s\n", *service)
	fmt.Printf("  Agent:     %s\n", *agentID)
	fmt.Printf("  ExpiresIn: %ds\n", resp.ExpiresIn)
	fmt.Printf("  Max Calls: %d\n", *calls)
}

func runVerify(args []string) {
	cfg, _ := config.LoadConfig()
	v, err := vault.NewVault(cfg.DBPath, cfg.VaultKey)
	if err != nil {
		log.Fatalf("verify error: %v", err)
	}
	defer v.Close()

	al, err := audit.NewLogger(v.DB())
	if err != nil {
		log.Fatalf("verify audit logger error: %v", err)
	}

	rep, err := al.VerifyChain()
	if err != nil {
		log.Fatalf("verification execution error: %v", err)
	}

	if rep.Valid {
		fmt.Printf("✓ Cryptographic Audit Trail Verified (SOC-2/HIPAA Grade)\n")
		fmt.Printf("  Total Blocks: %d\n", rep.TotalBlocks)
		fmt.Printf("  Tip Hash:     %s\n", rep.TipHash)
	} else {
		fmt.Printf("✗ INTEGRITY VIOLATION at block sequence #%d!\n", rep.BrokenSeq)
		fmt.Printf("  Details: %s\n", rep.Error)
		os.Exit(1)
	}
}

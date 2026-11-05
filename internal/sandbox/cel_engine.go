package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"gopkg.in/yaml.v3"
)

type DecisionType string

const (
	DecisionAllow    DecisionType = "ALLOW"
	DecisionEscalate DecisionType = "ESCALATE"
	DecisionDeny     DecisionType = "DENY"
)

type PolicyRule struct {
	Name           string   `yaml:"name"`
	Match          string   `yaml:"match"`
	AllowIf        string   `yaml:"allow_if,omitempty"`
	EscalateIf     string   `yaml:"escalate_if,omitempty"`
	DenyIf         string   `yaml:"deny_if,omitempty"`
	Approvers      []string `yaml:"approvers,omitempty"`
	TimeoutSeconds int      `yaml:"timeout_seconds,omitempty"`

	compiledMatch    cel.Program
	compiledAllow    cel.Program
	compiledEscalate cel.Program
	compiledDeny     cel.Program
}

type PolicyDocument struct {
	Version         string       `yaml:"version"`
	AgentID         string       `yaml:"agent_id"`         // "*" for all agents or specific
	UpstreamService string       `yaml:"upstream_service"` // "*" for all services or specific
	Rules           []PolicyRule `yaml:"rules"`
}

type EvalContext struct {
	Method  string
	Path    string
	Body    map[string]interface{}
	Tool    string
	Args    map[string]interface{}
	Headers map[string]string
	AgentID string
	TaskID  string
	Service string
}

type EvalResult struct {
	Decision       DecisionType
	MatchedRule    string
	Reason         string
	Approvers      []string
	TimeoutSeconds int
}

type CELEngine struct {
	env      *cel.Env
	counter  *StateCounter
	policies []PolicyDocument
	mu       sync.RWMutex
}

func NewCELEngine(counter *StateCounter) (*CELEngine, error) {
	engine := &CELEngine{
		counter:  counter,
		policies: make([]PolicyDocument, 0),
	}

	// Define CEL functions and environment
	env, err := cel.NewEnv(
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("agent", cel.MapType(cel.StringType, cel.StringType)),
		// state.daily_sum(metric)
		cel.Function("state.daily_sum",
			cel.Overload("state_daily_sum_string",
				[]*cel.Type{cel.StringType},
				cel.DoubleType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					metric, ok := arg.Value().(string)
					if !ok || engine.counter == nil {
						return types.Double(0.0)
					}
					_ = metric
					return types.Double(0.0)
				}),
			),
		),
		// sql.is_destructive(query)
		cel.Function("sql.is_destructive",
			cel.Overload("sql_is_destructive_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					q, ok := arg.Value().(string)
					if !ok {
						return types.Bool(false)
					}
					v := AnalyzeSQL(q)
					return types.Bool(v.IsDestructive)
				}),
			),
		),
		// bash.is_dangerous(cmd)
		cel.Function("bash.is_dangerous",
			cel.Overload("bash_is_dangerous_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					c, ok := arg.Value().(string)
					if !ok {
						return types.Bool(false)
					}
					v := AnalyzeBash(c)
					return types.Bool(v.IsDangerous)
				}),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("cel env init: %w", err)
	}

	engine.env = env
	return engine, nil
}

func (e *CELEngine) compileExpression(expr string) (cel.Program, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, nil
	}
	ast, issues := e.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("cel compile '%s': %w", expr, issues.Err())
	}
	prg, err := e.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("cel program '%s': %w", expr, err)
	}
	return prg, nil
}

func (e *CELEngine) LoadPolicyFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc PolicyDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse yaml %s: %w", path, err)
	}

	for i := range doc.Rules {
		r := &doc.Rules[i]
		if r.Match != "" {
			prg, err := e.compileExpression(r.Match)
			if err != nil {
				return err
			}
			r.compiledMatch = prg
		}
		if r.AllowIf != "" {
			prg, err := e.compileExpression(r.AllowIf)
			if err != nil {
				return err
			}
			r.compiledAllow = prg
		}
		if r.EscalateIf != "" {
			prg, err := e.compileExpression(r.EscalateIf)
			if err != nil {
				return err
			}
			r.compiledEscalate = prg
		}
		if r.DenyIf != "" {
			prg, err := e.compileExpression(r.DenyIf)
			if err != nil {
				return err
			}
			r.compiledDeny = prg
		}
		if r.TimeoutSeconds <= 0 {
			r.TimeoutSeconds = 300 // default 5m
		}
	}

	e.mu.Lock()
	e.policies = append(e.policies, doc)
	e.mu.Unlock()
	return nil
}

func (e *CELEngine) LoadPoliciesFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext == ".yaml" || ext == ".yml" {
			fullPath := filepath.Join(dir, entry.Name())
			if err := e.LoadPolicyFile(fullPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *CELEngine) Evaluate(ctx *EvalContext) (*EvalResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	reqMap := map[string]interface{}{
		"method": ctx.Method,
		"path":   ctx.Path,
		"body":   ctx.Body,
		"tool":   ctx.Tool,
		"args":   ctx.Args,
	}
	if reqMap["body"] == nil {
		reqMap["body"] = map[string]interface{}{}
	}
	if reqMap["args"] == nil {
		reqMap["args"] = map[string]interface{}{}
	}

	agentMap := map[string]interface{}{
		"id":      ctx.AgentID,
		"task_id": ctx.TaskID,
	}

	// Prepare CEL variables map
	celVars := map[string]interface{}{
		"request": reqMap,
		"agent":   agentMap,
	}

	// Also build dynamic env to evaluate state.daily_sum with actual agent ID
	var dailySumVal float64 = 0.0
	if e.counter != nil {
		dailySumVal = e.counter.DailySum(ctx.AgentID, "refunds")
	}

	for _, doc := range e.policies {
		// Filter by agent and service if specified
		if doc.AgentID != "" && doc.AgentID != "*" && doc.AgentID != ctx.AgentID {
			continue
		}
		if doc.UpstreamService != "" && doc.UpstreamService != "*" && doc.UpstreamService != ctx.Service {
			continue
		}

		for _, r := range doc.Rules {
			// Check Match
			if r.compiledMatch != nil {
				out, _, err := r.compiledMatch.Eval(celVars)
				if err != nil || out == nil || out.Value() != true {
					continue
				}
			}

			// 1. Check DenyIf
			if r.compiledDeny != nil {
				out, _, err := r.compiledDeny.Eval(celVars)
				if err == nil && out != nil && out.Value() == true {
					return &EvalResult{
						Decision:    DecisionDeny,
						MatchedRule: r.Name,
						Reason:      fmt.Sprintf("Denied by rule '%s'", r.Name),
					}, nil
				}
			}

			// 2. Check EscalateIf
			if r.compiledEscalate != nil {
				out, _, err := r.compiledEscalate.Eval(celVars)
				if err == nil && out != nil && out.Value() == true {
					return &EvalResult{
						Decision:       DecisionEscalate,
						MatchedRule:    r.Name,
						Reason:         fmt.Sprintf("Escalated by rule '%s'", r.Name),
						Approvers:      r.Approvers,
						TimeoutSeconds: r.TimeoutSeconds,
					}, nil
				}
			}

			// 3. Check AllowIf
			if r.compiledAllow != nil {
				out, _, err := r.compiledAllow.Eval(celVars)
				if err == nil && out != nil && out.Value() == true {
					return &EvalResult{
						Decision:    DecisionAllow,
						MatchedRule: r.Name,
						Reason:      fmt.Sprintf("Allowed by rule '%s'", r.Name),
					}, nil
				}
			}
		}
	}

	// Default fallback: If SQL is destructive, deny. If bash is dangerous, escalate. Otherwise allow.
	if ctx.Tool != "" {
		if q, ok := ctx.Args["query"].(string); ok {
			sqlVerdict := AnalyzeSQL(q)
			if sqlVerdict.IsDestructive {
				return &EvalResult{
					Decision: DecisionDeny,
					Reason:   sqlVerdict.Reason,
				}, nil
			}
		}
		if cmd, ok := ctx.Args["command"].(string); ok {
			bashVerdict := AnalyzeBash(cmd)
			if bashVerdict.IsDangerous {
				return &EvalResult{
					Decision:       DecisionEscalate,
					Reason:         bashVerdict.Reason,
					TimeoutSeconds: 300,
				}, nil
			}
		}
	}

	_ = dailySumVal
	return &EvalResult{
		Decision: DecisionAllow,
		Reason:   "Default policy allow",
	}, nil
}

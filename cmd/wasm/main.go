// Command wasm is the browser entry point for sing-vis. Built with
// `GOOS=js GOARCH=wasm`, it exposes a single JS-callable function,
// `singvisAnalyze`, that runs the exact same internal/engine analysis the old
// HTTP server did — only now it runs entirely in the browser (in a Web Worker).
//
// Under js/wasm, net/http transparently uses the browser Fetch API, so the DoH
// resolver and remote rule-set fetching keep working (subject to CORS).
//
//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"syscall/js"

	"sing-vis/internal/dnsx"
	"sing-vis/internal/engine"
)

// analyzeRequest is the single JSON argument passed from JS. It mirrors the old
// POST /api/analyze body.
type analyzeRequest struct {
	Config         string                        `json:"config"`
	Inputs         []string                      `json:"inputs"`
	RuleSetFiles   map[string]engine.RuleSetFile `json:"ruleSetFiles"`
	DoHServer      string                        `json:"dohServer"`
	Network        string                        `json:"network"`        // optional: tcp/udp assumption
	Protocol       string                        `json:"protocol"`       // optional: sniffed-protocol assumption
	AssumeResolved *bool                         `json:"assumeResolved"` // default true
}

const defaultDoHServer = "https://1.1.1.1/dns-query"

func main() {
	js.Global().Set("singvisAnalyze", js.FuncOf(analyze))
	// Signal readiness to the host (worker) so it need not poll.
	if ready := js.Global().Get("singvisReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}
	select {} // keep the Go runtime alive to service calls
}

// analyze is the JS-facing entry point. It takes one JSON string argument and
// returns a Promise<string> that resolves to the marshaled engine.Result (or
// rejects with an Error). The work runs in a goroutine so the JS event loop is
// never blocked while DoH / rule-set fetches are in flight.
func analyze(_ js.Value, args []js.Value) any {
	var input string
	if len(args) > 0 && args[0].Type() == js.TypeString {
		input = args[0].String()
	}
	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]
		go func() {
			out, err := runAnalyze(input)
			if err != nil {
				reject.Invoke(jsError(err))
				return
			}
			resolve.Invoke(out)
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

func runAnalyze(input string) (string, error) {
	var req analyzeRequest
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		return "", fmt.Errorf("invalid request: %w", err)
	}
	doh := req.DoHServer
	if doh == "" {
		doh = defaultDoHServer
	}
	assumeResolved := true
	if req.AssumeResolved != nil {
		assumeResolved = *req.AssumeResolved
	}
	result, err := engine.Analyze(context.Background(), engine.Request{
		Config:         req.Config,
		Inputs:         req.Inputs,
		RuleSetFiles:   req.RuleSetFiles,
		Network:        req.Network,
		Protocol:       req.Protocol,
		AssumeResolved: assumeResolved,
		Resolver:       dnsx.NewDoHResolver(doh),
	})
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func jsError(err error) js.Value {
	return js.Global().Get("Error").New(err.Error())
}

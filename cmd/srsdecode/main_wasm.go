// Browser entry point for the .srs decoder. Built with GOOS=js GOARCH=wasm, it
// exposes a single JS-callable function `singvisDecodeSRS(base64) -> Promise<string>`
// that returns the recovered source rules as JSON. This is the only Go/wasm the
// JS engine keeps, and it is loaded lazily — only when a config actually uses a
// binary (.srs) rule set.
//
//go:build js && wasm

package main

import (
	"encoding/base64"
	"syscall/js"
)

func main() {
	js.Global().Set("singvisDecodeSRS", js.FuncOf(decodeJS))
	if ready := js.Global().Get("singvisSRSReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}
	select {} // keep the Go runtime alive to service calls
}

// decodeJS takes one base64 string argument (the .srs bytes) and returns a
// Promise<string> resolving to the recovered-rules JSON (or rejecting with Error).
func decodeJS(_ js.Value, args []js.Value) any {
	var input string
	if len(args) > 0 && args[0].Type() == js.TypeString {
		input = args[0].String()
	}
	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]
		go func() {
			data, err := base64.StdEncoding.DecodeString(input)
			if err != nil {
				reject.Invoke(jsError(err.Error()))
				return
			}
			out, err := decode(data)
			if err != nil {
				reject.Invoke(jsError(err.Error()))
				return
			}
			resolve.Invoke(string(out))
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

func jsError(msg string) js.Value {
	return js.Global().Get("Error").New(msg)
}

// Native CLI build of the .srs decoder, used by the test harness (as the
// injected decodeSRS) and to generate .srs test fixtures. Not shipped to the
// browser — that path is main_wasm.go.
//
//   ...| go run ./cmd/srsdecode            # stdin: base64 .srs  -> stdout: JSON rules
//   ...| go run ./cmd/srsdecode -compile   # stdin: source JSON  -> stdout: base64 .srs
//
//go:build !js

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

func main() {
	compile := flag.Bool("compile", false, "compile source rule-set JSON (stdin) to base64 .srs (stdout)")
	flag.Parse()

	in, err := io.ReadAll(os.Stdin)
	must(err)

	if *compile {
		out, err := compileSRS(in)
		must(err)
		fmt.Print(base64.StdEncoding.EncodeToString(out))
		return
	}

	data, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(in)))
	must(err)
	out, err := decode(data)
	must(err)
	os.Stdout.Write(out)
}

func compileSRS(sourceJSON []byte) ([]byte, error) {
	var compat option.PlainRuleSetCompat
	if err := sjson.UnmarshalContext(context.Background(), sourceJSON, &compat); err != nil {
		return nil, err
	}
	plain, err := compat.Upgrade()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := srs.Write(&buf, plain, C.RuleSetVersionCurrent); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

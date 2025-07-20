package preload

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Tencent/AI-Infra-Guard/common/fingerprints/parser"
	"github.com/Tencent/AI-Infra-Guard/pkg/httpx"
)

func newHTTPX(t *testing.T) *httpx.HTTPX {
	t.Helper()
	httpOptions := &httpx.HTTPOptions{
		Timeout:         time.Second,
		RetryMax:        1,
		FollowRedirects: false,
	}
	hp, err := httpx.NewHttpx(httpOptions)
	if err != nil {
		t.Fatalf("new httpx: %v", err)
	}
	return hp
}

func TestEvalFpFuzzVersion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello ver 0.9"))
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	yamlData := []byte(`
info:
  name: testfp
  author: test
  severity: info
http:
  - method: GET
    path: '/'
    matchers:
      - body="hello"
fuzzversion:
  - path: '/api'
    version_range: '>=0.8.0'
  - path: '/'
    pattern: 'ver 0.9'
    version_range: '>=0.9.0'
`)
	fp, err := parser.InitFingerPrintFromData(yamlData)
	if err != nil {
		t.Fatalf("parse yaml: %v", err)
	}
	hp := newHTTPX(t)
	ver, err := EvalFpVersion(srv.URL, hp, *fp)
	if err != nil {
		t.Fatalf("eval version: %v", err)
	}
	if ver != ">=0.8.0" && ver != ">=0.9.0" {
		t.Fatalf("unexpected version: %s", ver)
	}
}

func TestEvalFpVersionIgnoreFuzz(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/meta", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("version:1.2"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	yamlData := []byte(`
info:
  name: testfp
  author: test
  severity: info
http:
  - method: GET
    path: '/'
    matchers:
      - body=""
version:
  - method: GET
    path: '/meta'
    extractor:
      part: body
      group: '1'
      regex: 'version:(\d+\.\d+)'
fuzzversion:
  - path: '/api'
    version_range: '>=0.8.0'
`)
	fp, err := parser.InitFingerPrintFromData(yamlData)
	if err != nil {
		t.Fatalf("parse yaml: %v", err)
	}
	hp := newHTTPX(t)
	ver, err := EvalFpVersion(srv.URL, hp, *fp)
	if err != nil {
		t.Fatalf("eval version: %v", err)
	}
	if ver != "1.2" {
		t.Fatalf("expect 1.2 got %s", ver)
	}
}

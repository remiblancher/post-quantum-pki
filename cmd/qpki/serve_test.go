package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// resetServeFlags resets all serve command flags to their default values.
func resetServeFlags() {
	servePort = 0
	serveOCSPPort = 0
	serveTSAPort = 0
	serveHost = ""
	serveCADir = ""
	serveTLSCert = ""
	serveTLSKey = ""
}

// =============================================================================
// Serve Command Tests
// =============================================================================

func TestF_Serve_MissingCADir(t *testing.T) {
	resetServeFlags()

	_, err := executeCommand(rootCmd, "serve")
	assertError(t, err)
}

// =============================================================================
// applyServeEnvVars Tests
// =============================================================================

func TestU_ApplyServeEnvVars(t *testing.T) {
	t.Run("QPKI_PORT sets servePort", func(t *testing.T) {
		resetServeFlags()
		t.Setenv("QPKI_PORT", "9090")

		applyServeEnvVars()

		if servePort != 9090 {
			t.Errorf("expected servePort=9090, got %d", servePort)
		}
	})

	t.Run("QPKI_OCSP_PORT sets serveOCSPPort", func(t *testing.T) {
		resetServeFlags()
		t.Setenv("QPKI_OCSP_PORT", "9091")

		applyServeEnvVars()

		if serveOCSPPort != 9091 {
			t.Errorf("expected serveOCSPPort=9091, got %d", serveOCSPPort)
		}
	})

	t.Run("QPKI_TSA_PORT sets serveTSAPort", func(t *testing.T) {
		resetServeFlags()
		t.Setenv("QPKI_TSA_PORT", "9092")

		applyServeEnvVars()

		if serveTSAPort != 9092 {
			t.Errorf("expected serveTSAPort=9092, got %d", serveTSAPort)
		}
	})

	t.Run("QPKI_CA_DIR sets serveCADir", func(t *testing.T) {
		resetServeFlags()
		t.Setenv("QPKI_CA_DIR", "/tmp/ca")

		applyServeEnvVars()

		if serveCADir != "/tmp/ca" {
			t.Errorf("expected serveCADir=/tmp/ca, got %s", serveCADir)
		}
	})

	t.Run("QPKI_TLS_CERT sets serveTLSCert", func(t *testing.T) {
		resetServeFlags()
		t.Setenv("QPKI_TLS_CERT", "cert.pem")

		applyServeEnvVars()

		if serveTLSCert != "cert.pem" {
			t.Errorf("expected serveTLSCert=cert.pem, got %s", serveTLSCert)
		}
	})

	t.Run("QPKI_TLS_KEY sets serveTLSKey", func(t *testing.T) {
		resetServeFlags()
		t.Setenv("QPKI_TLS_KEY", "key.pem")

		applyServeEnvVars()

		if serveTLSKey != "key.pem" {
			t.Errorf("expected serveTLSKey=key.pem, got %s", serveTLSKey)
		}
	})

	t.Run("flag values take precedence over env vars", func(t *testing.T) {
		resetServeFlags()

		// Simulate flag values already set
		servePort = 7070
		serveOCSPPort = 7071
		serveTSAPort = 7072
		serveCADir = "/flag/ca"
		serveTLSCert = "flag-cert.pem"
		serveTLSKey = "flag-key.pem"

		// Set env vars that should NOT override
		t.Setenv("QPKI_PORT", "9090")
		t.Setenv("QPKI_OCSP_PORT", "9091")
		t.Setenv("QPKI_TSA_PORT", "9092")
		t.Setenv("QPKI_CA_DIR", "/env/ca")
		t.Setenv("QPKI_TLS_CERT", "env-cert.pem")
		t.Setenv("QPKI_TLS_KEY", "env-key.pem")

		applyServeEnvVars()

		if servePort != 7070 {
			t.Errorf("expected servePort=7070 (flag), got %d", servePort)
		}
		if serveOCSPPort != 7071 {
			t.Errorf("expected serveOCSPPort=7071 (flag), got %d", serveOCSPPort)
		}
		if serveTSAPort != 7072 {
			t.Errorf("expected serveTSAPort=7072 (flag), got %d", serveTSAPort)
		}
		if serveCADir != "/flag/ca" {
			t.Errorf("expected serveCADir=/flag/ca (flag), got %s", serveCADir)
		}
		if serveTLSCert != "flag-cert.pem" {
			t.Errorf("expected serveTLSCert=flag-cert.pem (flag), got %s", serveTLSCert)
		}
		if serveTLSKey != "flag-key.pem" {
			t.Errorf("expected serveTLSKey=flag-key.pem (flag), got %s", serveTLSKey)
		}
	})

	t.Run("unset env vars leave defaults", func(t *testing.T) {
		resetServeFlags()

		// Ensure env vars are unset
		_ = os.Unsetenv("QPKI_PORT")
		_ = os.Unsetenv("QPKI_OCSP_PORT")
		_ = os.Unsetenv("QPKI_TSA_PORT")
		_ = os.Unsetenv("QPKI_CA_DIR")
		_ = os.Unsetenv("QPKI_TLS_CERT")
		_ = os.Unsetenv("QPKI_TLS_KEY")

		applyServeEnvVars()

		if servePort != 0 {
			t.Errorf("expected servePort=0, got %d", servePort)
		}
		if serveCADir != "" {
			t.Errorf("expected serveCADir=\"\", got %s", serveCADir)
		}
	})
}

// =============================================================================
// Handler Tests
// =============================================================================

func TestU_HandleOCSP(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/ocsp", nil)
	w := httptest.NewRecorder()

	handleOCSP(w, req)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("expected status 501, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got == "" {
		t.Error("expected non-empty response body")
	}
}

func TestU_HandleTSA(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/tsa", nil)
	w := httptest.NewRecorder()

	handleTSA(w, req)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("expected status 501, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got == "" {
		t.Error("expected non-empty response body")
	}
}

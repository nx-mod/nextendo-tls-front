// tls-front — terminaison TLS devant les services Nextendo qui ne parlent que HTTP.
//
// En production c'est Traefik qui tient ce rôle. En local il n'y a rien, et
// nextendo-account fait http.ListenAndServe tout court : quand la console suit
// « Lier un compte Nintendo », nnAccount résout accounts.nintendo.com vers nous
// et ouvre une session TLS que personne ne termine.
//
// sni-router reste un passe-plat TCP (il ne déchiffre rien) et nous envoie les
// connexions dont le SNI vaut accounts.nintendo.com ou *.baas.nintendo.com.
// Ici on termine le TLS avec le certificat auto-signé de localcerts — la console
// l'accepte grâce aux patches disable_ca_verification déjà posés sur la SD — et
// on relaie en clair vers le backend HTTP correspondant au Host.
package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func headerDump(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k + ": " + v + "\n")
		}
	}
	return b.String()
}

func mustProxy(target string) *httputil.ReverseProxy {
	u, err := url.Parse(target)
	if err != nil {
		log.Fatalf("backend %q: %v", target, err)
	}
	return httputil.NewSingleHostReverseProxy(u)
}

func main() {
	addr := envOr("TLSFRONT_LISTEN", ":8455")
	cert := envOr("TLSFRONT_CERT", "../localcerts/cert.pem")
	key := envOr("TLSFRONT_KEY", "../localcerts/key.pem")

	account := mustProxy(envOr("TLSFRONT_ACCOUNT", "http://127.0.0.1:8080"))
	baas := mustProxy(envOr("TLSFRONT_BAAS", "http://127.0.0.1:8453"))

	// /connect/... = les endpoints nnAccount (« importer un compte » sur la
	// console). Le service de comptes local ne les implémente pas — il ne sert que
	// /api, /avatars, /internal — donc on relaie vers le vrai Nextendo, comme
	// baas-proxy le fait déjà pour BAAS. Le reste (/api, la page d'inscription)
	// continue d'être servi localement.
	// TLSFRONT_NNACCOUNT: the local Nintendo Account service (nextendo-nnaccount-nx). When set, it answers
	// /connect, /1.0.0/certificates and api.accounts.nintendo.com, and nothing is relayed upstream.
	var nnaccount *httputil.ReverseProxy
	if v := os.Getenv("TLSFRONT_NNACCOUNT"); v != "" {
		nnaccount = mustProxy(v)
		log.Printf("[tls-front] Nintendo Account served locally by %s", v)
	}

	upstream := envOr("TLSFRONT_UPSTREAM", "https://51.178.29.194")
	connect := mustProxy(upstream)
	connect.Transport = &http.Transport{
		// Certificat du VPS présenté pour une IP : on vérifie le nom nous-mêmes
		// via ServerName, pas la chaîne.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "accounts.nintendo.com"},
	}
	// NewSingleHostReverseProxy réécrit Host avec celui de l'upstream ; nnAccount
	// exige accounts.nintendo.com, sinon le VPS ne route pas.
	connectDirector := connect.Director
	connect.Director = func(r *http.Request) {
		connectDirector(r)
		r.Host = "accounts.nintendo.com"
	}
	// TLSFRONT_CAPTURE=<file>: record each /connect exchange (request and response, bodies included) so the
	// endpoints can be implemented locally instead of relayed. Off unless set.
	if capPath := os.Getenv("TLSFRONT_CAPTURE"); capPath != "" {
		capFile, err := os.OpenFile(capPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatalf("capture %s: %v", capPath, err)
		}
		capLog := log.New(capFile, "", log.LstdFlags)
		inner := connect.Director
		connect.Director = func(r *http.Request) {
			if r.Body != nil {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				capLog.Printf(">>> %s %s%s\n%s\n%s\n", r.Method, r.Host, r.URL.RequestURI(), headerDump(r.Header), body)
			}
			inner(r)
		}
		connect.ModifyResponse = func(resp *http.Response) error {
			body, _ := io.ReadAll(resp.Body)
			resp.Body = io.NopCloser(bytes.NewReader(body))
			capLog.Printf("<<< %d %s\n%s\n%s\n", resp.StatusCode, resp.Request.URL.Path, headerDump(resp.Header), body)
			return nil
		}
		log.Printf("[tls-front] capturing /connect exchanges to %s", capPath)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}

		p := account
		which := "account"
		switch {
		case strings.HasSuffix(host, "baas.nintendo.com"):
			p, which = baas, "baas"
		case nnaccount != nil && (host == "api.accounts.nintendo.com" || host == "cdn.accounts.nintendo.com" ||
			strings.HasPrefix(r.URL.Path, "/connect/") || r.URL.Path == "/1.0.0/certificates"):
			p, which = nnaccount, "nnaccount"
		case strings.HasPrefix(r.URL.Path, "/connect/"):
			p, which = connect, "upstream"
		}

		log.Printf("%s %s%s -> %s", r.Method, host, r.URL.Path, which)
		// Le backend parle HTTP : sans ça il croit répondre en clair et fabrique
		// des URL http:// dans les redirections de l'OAuth nnAccount.
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", host)
		p.ServeHTTP(w, r)
	})

	// HTTP/1.1 only: Go offers h2 by default, and the console's browser applet completed the handshake and
	// then dropped the connection without a request. nnAccount's libcurl uses HTTP/1.1 anyway.
	// Each ClientHello and connection state is logged, so a client that gives up shows what it offered.
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS10,
		NextProtos: []string{"http/1.1"},
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			log.Printf("hello from %s sni=%q versions=%x alpn=%q suites=%d", hi.Conn.RemoteAddr(), hi.ServerName, hi.SupportedVersions, hi.SupportedProtos, len(hi.CipherSuites))
			return nil, nil
		},
	}
	// TLSFRONT_MAX_TLS12=1: offer TLS 1.2 at most, for clients whose TLS 1.3 fails (the console's browser
	// dropped every TLS 1.3 handshake right after the ClientHello).
	if os.Getenv("TLSFRONT_MAX_TLS12") == "1" {
		tlsConf.MaxVersion = tls.VersionTLS12
		log.Printf("[tls-front] TLS 1.2 at most")
	}
	srv := &http.Server{
		Addr:         addr,
		Handler:      h,
		TLSConfig:    tlsConf,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ConnState: func(c net.Conn, st http.ConnState) {
			if st == http.StateActive || st == http.StateClosed || st == http.StateHijacked {
				extra := ""
				if tc, ok := c.(*tls.Conn); ok && st != http.StateClosed {
					cs := tc.ConnectionState()
					extra = fmt.Sprintf(" tls=%x alpn=%q", cs.Version, cs.NegotiatedProtocol)
				}
				log.Printf("conn %s %s%s", c.RemoteAddr(), st, extra)
			}
		},
	}
	log.Printf("[tls-front] écoute %s (cert=%s) account/baas", addr, cert)
	log.Fatal(srv.ListenAndServeTLS(cert, key))
}

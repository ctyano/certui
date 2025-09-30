package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid" // Required for unique Profile Identifiers
	vault "github.com/hashicorp/vault/api"

	// Using the alternative library recommended by the user to ensure pkcs12.Encode is available.
	"golang.org/x/oauth2"
	pkcs12go "software.sslmate.com/src/go-pkcs12"
)

//go:embed index.html
var content embed.FS // Embed the index.html file into the binary

// Global variables for configuration.
var (
	DEFAULT_OIDC_CLIENT_ID      = "certui"
	DEFAULT_OIDC_CLIENT_SECRET  = "certui"
	DEFAULT_OIDC_ISSUER         = "http://127.0.0.1:5556/dex"
	DEFAULT_OIDC_SCOPES         = "openid email profile"
	DEFAULT_OIDC_LISTEN_ADDRESS = ":8080"

	DEFAULT_SIGNER_VAULT_BASE_URL = "http://127.0.0.1:8200"
	DEFAULT_SIGNER_VAULT_JWT_ROLE = "jwt"
	DEFAULT_SIGNER_VAULT_PKI_ROLE = "issuers"
	DEFAULT_SIGNER_VAULT_PKI_NAME = "rootca"

	// Derived/Internal configuration
	dexRedirectURI = "http://127.0.0.1" + DEFAULT_OIDC_LISTEN_ADDRESS + "/auth/callback"
	vaultPKIEngine = DEFAULT_SIGNER_VAULT_PKI_NAME
)

var (
	oidcVerifier *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	// FIX: Use template.ParseFS to load the template from the embedded content
	tmpl = template.Must(template.New("home").ParseFS(content, "index.html"))
)

// generateRandomState creates a cryptographically secure random string for CSRF protection.
func generateRandomState() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func main() {
	// Initialize OIDC provider.
	// NOTE: InsecureSkipVerify is used for development/local environments like Dex
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	ctx := oidc.ClientContext(context.Background(), client)

	provider, err := oidc.NewProvider(ctx, DEFAULT_OIDC_ISSUER)
	if err != nil {
		log.Fatalf("Failed to initialize OIDC provider: %v", err)
	}

	oidcVerifier = provider.Verifier(&oidc.Config{ClientID: DEFAULT_OIDC_CLIENT_ID})
	oauth2Config = oauth2.Config{
		ClientID:     DEFAULT_OIDC_CLIENT_ID,
		ClientSecret: DEFAULT_OIDC_CLIENT_SECRET,
		RedirectURL:  dexRedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       strings.Split(DEFAULT_OIDC_SCOPES, " "),
	}

	// Set up HTTP routes.
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/auth/callback", handleCallback)
	http.HandleFunc("/download", handleHome)                 // Serves the page that triggers the download form
	http.HandleFunc("/api/mobileconfig", handleMobileConfig) // New POST endpoint for .mobileconfig

	log.Printf("Starting server on http://127.0.0.1%s", DEFAULT_OIDC_LISTEN_ADDRESS)
	if err := http.ListenAndServe(DEFAULT_OIDC_LISTEN_ADDRESS, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// handleHome serves the main HTML page (login view or download view).
func handleHome(w http.ResponseWriter, r *http.Request) {
	// FIX: Use ExecuteTemplate to specifically execute the template named "index.html"
	if err := tmpl.ExecuteTemplate(w, "index.html", nil); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

// handleLogin generates a secure random state, stores it in a cookie, and redirects to Dex.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateRandomState()
	if err != nil {
		http.Error(w, "Error generating state", http.StatusInternalServerError)
		return
	}

	// Store state in a secure, http-only cookie for verification later
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(5 * time.Minute),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

// handleCallback validates OIDC and redirects the client to the /download page with the ID Token.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	// 1. Get state from cookie
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "Missing or invalid state cookie (Possible CSRF)", http.StatusBadRequest)
		return
	}

	// 2. Clear the state cookie immediately after retrieval
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})

	// 3. Verify state parameter against cookie value
	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "State did not match (Possible CSRF)", http.StatusBadRequest)
		return
	}

	oauth2Token, err := oauth2Config.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No ID Token found", http.StatusInternalServerError)
		return
	}

	// Verify the token before passing it to the client
	_, err = oidcVerifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to the download page, passing the validated token as a query parameter.
	http.Redirect(w, r, fmt.Sprintf("/download?token=%s", rawIDToken), http.StatusFound)
}

// MobileConfig generation related structs/data
type downloadRequest struct {
	IDToken  string `form:"id_token"`
	Password string `form:"password"`
}

// handleMobileConfig is the POST endpoint that handles Vault access and .mobileconfig generation.
func handleMobileConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Parse the POST form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	reqBody := downloadRequest{
		IDToken:  r.FormValue("id_token"),
		Password: r.FormValue("password"),
	}

	if reqBody.IDToken == "" || reqBody.Password == "" {
		http.Error(w, "Missing ID Token or Password in request", http.StatusBadRequest)
		return
	}

	// --- Vault Integration ---
	vaultClient, err := vault.NewClient(&vault.Config{Address: DEFAULT_SIGNER_VAULT_BASE_URL})
	if err != nil {
		log.Printf("Vault client error: %v", err)
		http.Error(w, "Failed to create Vault client", http.StatusInternalServerError)
		return
	}

	// 2. Authenticate with Vault using the JWT token
	loginPayload := map[string]interface{}{
		"jwt":  reqBody.IDToken,
		"role": DEFAULT_SIGNER_VAULT_JWT_ROLE,
	}

	authResponse, err := vaultClient.Logical().Write("auth/jwt/login", loginPayload)
	if err != nil {
		log.Printf("Vault JWT login failed: %v", err)
		http.Error(w, "Vault authentication failed.", http.StatusUnauthorized)
		return
	}
	if authResponse.Auth == nil {
		http.Error(w, "Vault authentication response was empty", http.StatusUnauthorized)
		return
	}
	vaultClient.SetToken(authResponse.Auth.ClientToken)

	// 3. Extract email claim for CN
	idToken, err := oidcVerifier.Verify(context.Background(), reqBody.IDToken)
	if err != nil {
		http.Error(w, "Token failed verification during POST", http.StatusUnauthorized)
		return
	}
	var claims struct {
		Email string `json:"email"`
	}
	idToken.Claims(&claims)
	if claims.Email == "" {
		http.Error(w, "Token lacks required email claim", http.StatusForbidden)
		return
	}

	// 4. Request a certificate from the PKI secrets engine.
	certRequestPayload := map[string]interface{}{
		"common_name": claims.Email,
		"ttl":         "72h",
	}

	issuePath := fmt.Sprintf("%s/issue/%s", vaultPKIEngine, DEFAULT_SIGNER_VAULT_PKI_ROLE)
	secret, err := vaultClient.Logical().Write(issuePath, certRequestPayload)
	if err != nil {
		log.Printf("Vault PKI issue failed: %v", err)
		http.Error(w, "Failed to issue certificate from Vault.", http.StatusInternalServerError)
		return
	}

	data := secret.Data
	if data == nil {
		http.Error(w, "Vault response did not contain certificate data", http.StatusInternalServerError)
		return
	}
	certificate := data["certificate"].(string)
	privateKey := data["private_key"].(string)
	caChain := data["ca_chain"].([]interface{})

	// 5. PKCS#12 BUNDLING (Required for .mobileconfig IDENTITY payload)

	pemBlock, _ := pem.Decode([]byte(privateKey))
	if pemBlock == nil || pemBlock.Type != "RSA PRIVATE KEY" {
		http.Error(w, "Failed to parse private key PEM", http.StatusInternalServerError)
		return
	}
	priv, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		http.Error(w, "Failed to parse private key", http.StatusInternalServerError)
		return
	}

	pemBlock, _ = pem.Decode([]byte(certificate))
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		http.Error(w, "Failed to parse certificate PEM", http.StatusInternalServerError)
		return
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		http.Error(w, "Failed to parse certificate", http.StatusInternalServerError)
		return
	}

	var caCerts []*x509.Certificate
	for _, rawCa := range caChain {
		if caStr, ok := rawCa.(string); ok {
			block, _ := pem.Decode([]byte(caStr))
			if block != nil {
				ca, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					caCerts = append(caCerts, ca)
				}
			}
		}
	}

	// Combine the user certificate and the CA chain
	allCerts := []*x509.Certificate{cert}
	allCerts = append(allCerts, caCerts...)

	// Use the 5-argument signature: Encode(rand io.Reader, privateKey interface{}, certificates []*x509.Certificate, password string)
	pfxBytes, err := pkcs12go.Encode(rand.Reader, priv, allCerts[0], nil, reqBody.Password)
	if err != nil {
		log.Printf("PKCS#12 encoding failed: %v", err)
		http.Error(w, "Failed to generate PKCS#12 bundle", http.StatusInternalServerError)
		return
	}

	// Base64 encode the PKCS#12 bundle for inclusion in the XML profile
	b64Pfx := base64.StdEncoding.EncodeToString(pfxBytes)

	// --- MobileConfig Generation (XML) ---

	// Generate unique UUIDs for Profile and Identity Payload
	profileUUID := uuid.New().String()
	identityUUID := uuid.New().String()

	// The mobileconfig is an XML file using a specific DTD.
	// We use the identity payload type (com.apple.security.pkcs12) which requires the private key (inside the PFX).
	mobileConfigTemplate := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadContent</key>
            <data>%s</data>
            <key>PayloadDescription</key>
            <string>Certificate and Private Key</string>
            <key>PayloadDisplayName</key>
            <string>Client Identity (%s)</string>
            <key>PayloadIdentifier</key>
            <string>com.example.clientcert.%s</string>
            <key>PayloadType</key>
            <string>com.apple.security.pkcs12</string>
            <key>PayloadUUID</key>
            <string>%s</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>Password</key>
            <string>%s</string>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Installs client certificate for mTLS authentication.</string>
    <key>PayloadDisplayName</key>
    <string>Client Certificate for %s</string>
    <key>PayloadIdentifier</key>
    <string>com.example.clientcert.profile.%s</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>%s</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`

	mobileConfig := fmt.Sprintf(mobileConfigTemplate,
		b64Pfx,           // PayloadContent (Base64 PKCS#12)
		claims.Email,     // PayloadDisplayName
		identityUUID,     // PayloadIdentifier
		identityUUID,     // PayloadUUID
		reqBody.Password, // Password (PKCS#12 password)
		claims.Email,     // PayloadDisplayName
		profileUUID,      // PayloadIdentifier
		profileUUID,      // PayloadUUID
	)

	// 6. Serve the MobileConfig file for direct download
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"ClientCertProfile_%s.mobileconfig\"", time.Now().Format("20060102")))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(mobileConfig)))

	if _, err := w.Write([]byte(mobileConfig)); err != nil {
		log.Printf("Failed to write MobileConfig data: %v", err)
	}
}

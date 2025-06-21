package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ansxuman/go-touchid"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/psanford/awsso-agent/browser"
	"github.com/psanford/awsso-agent/client"
	"github.com/psanford/awsso-agent/config"
	"github.com/psanford/awsso-agent/internal/notify"
	"github.com/psanford/awsso-agent/messages"
	"github.com/psanford/awsso-agent/pinentry"
	"github.com/psanford/awsso-agent/u2f"
)

var (
	grantTypeDevice   = "urn:ietf:params:oauth:grant-type:device_code"
	grantTypeAuthCode = "authorization_code"
)

type server struct {
	mu      sync.Mutex
	creds   map[string]*ssoToken
	handler http.Handler
	conf    *config.Config
}

func (s *server) ListenAndServe() error {
	_, err := os.Stat(config.SocketPath())
	if err == nil {
		c := client.NewClientWithTimeout(1 * time.Second)
		err = c.Ping()
		if err == nil {
			return errors.New("Existing server already running")
		}

		os.Remove(config.SocketPath())
	}

	l, err := net.Listen("unix", config.SocketPath())
	if err != nil {
		return err
	}
	os.Chmod(config.SocketPath(), 0700)

	return http.Serve(l, s.handler)
}

func New(conf *config.Config) *server {
	s := &server{
		creds: make(map[string]*ssoToken),
		conf:  conf,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/ping", s.handlePing)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/list_accounts_roles", s.handleListAccountRoles)
	mux.HandleFunc("/profiles", s.handleListProfiles)
	mux.HandleFunc("/session", s.handleSession)
	mux.HandleFunc("/session_token", s.handleSessionToken)

	s.handler = mux

	return s
}

func (s *server) handlePing(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "pong")
}

func (s *server) confirmUserPresence(ctx context.Context, prompt string) error {
	if s.conf.UseTouchID {
		success, err := touchid.Auth(touchid.DeviceTypeAny, "awsso confirm")
		if err != nil {
			return err
		}
		if !success {
			return errors.New("touchid auth error")
		}

		return nil
	}

	if len(s.conf.FidoKeyHandles) == 0 && s.conf.AllowNoUserVerify {
		return nil
	}

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	confirmStop := make(chan struct{})
	verifyResult := make(chan error)

	go func() {
		ok, err := pinentry.Confirm(childCtx, fmt.Sprintf("Tap yubikey to confirm\n%s", prompt))
		if err != nil {
			log.Printf("confirm err: %s", err)
		}
		if !ok {
			close(confirmStop)
		}
	}()

	go func() {
		err := u2f.VerifyDevice(childCtx, s.conf.FidoKeyHandles)
		verifyResult <- err
	}()

	select {
	case <-confirmStop:
		return errors.New("user cancelled")
	case authErr := <-verifyResult:
		if authErr != nil {
			return errors.New("yubikey auth error")
		}
	}

	return nil
}

func (c *server) awsConfig(ctx context.Context, profile config.Profile) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(profile.Region),
	)
}

func (s *server) handleSession(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.ParseForm()

	profileID := r.FormValue("profile_id")
	roleName := r.Form.Get("role_name")
	accountID := r.Form.Get("account_id")
	accountName := r.Form.Get("accountName")
	if accountName == "" {
		accountName = "role"
	}
	userPresenceTokenBypassB64 := r.Form.Get("user_presence_bypass_token")

	profile, err := s.conf.FindProfile(profileID)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		log.Printf("Profile lookup failed for profile_id=%q, err=%q", r.FormValue("profile_id"), err)
		return
	}

	creds := s.creds[profile.ID]

	if creds == nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "No creds available")
		log.Printf("No creds found for profile=%q", profile.ID)
		return
	}

	if creds.Expiration.Before(time.Now()) {
		w.WriteHeader(400)
		fmt.Fprintf(w, "creds expired: %s", creds.Expiration)
		return
	}

	var validUserPresenceTokenBypass bool
	if userPresenceTokenBypassB64 != "" {
		userPresenceTokenBypass, err := base64.StdEncoding.DecodeString(userPresenceTokenBypassB64)
		if err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, "invalid user presence bypass token")
			return
		}

		now := time.Now()
		var (
			tokenExpired bool
		)
		for i := 0; i < len(creds.userPresenceTokenBypass); i++ {
			existingToken := creds.userPresenceTokenBypass[i]

			if existingToken.expiration.Before(now) {
				if subtle.ConstantTimeCompare(existingToken.token, userPresenceTokenBypass) == 1 {
					tokenExpired = true
				}

				// Remove expired element from slice
				creds.userPresenceTokenBypass = append(creds.userPresenceTokenBypass[:i], creds.userPresenceTokenBypass[i+1:]...)
				i--
			} else if subtle.ConstantTimeCompare(existingToken.token, userPresenceTokenBypass) == 1 {
				validUserPresenceTokenBypass = true
			}
		}

		if tokenExpired {
			w.WriteHeader(400)
			log.Printf("token expired failed")
			return
		}
	}

	if validUserPresenceTokenBypass {
		log.Printf(fmt.Sprintf("Auto approved: session\nprofile: %s\nrole: %s\naccountID: %s\n", profile.ID, roleName, accountID))
		clear := notify.ShowNotification(fmt.Sprintf("Auto approved: session\nprofile: %s\nrole: %s\naccountID: %s\n", profile.ID, roleName, accountID))
		go func() {
			time.Sleep(5 * time.Second)
			clear()
		}()
	} else {
		err = s.confirmUserPresence(r.Context(), fmt.Sprintf("req: session\nprofile: %s\nrole: %s\naccountID: %s\n", profile.ID, roleName, accountID))
		if err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, err.Error())
			log.Printf("Confirm user presence failed")
			return
		}
	}

	cfg, err := s.awsConfig(r.Context(), profile)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws config error: %s", err)
		return
	}

	ssoService := sso.NewFromConfig(cfg)
	roleResp, err := ssoService.GetRoleCredentials(r.Context(), &sso.GetRoleCredentialsInput{
		AccessToken: creds.AccessToken,
		AccountId:   &accountID,
		RoleName:    &roleName,
	})
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws get-role-credentials error: %s", err)
		return
	}

	exp := time.UnixMilli(roleResp.RoleCredentials.Expiration)
	outCreds := types.Credentials{
		AccessKeyId:     roleResp.RoleCredentials.AccessKeyId,
		SecretAccessKey: roleResp.RoleCredentials.SecretAccessKey,
		SessionToken:    roleResp.RoleCredentials.SessionToken,
		Expiration:      &exp,
	}

	result := messages.Credentials{
		Credentials: &outCreds,
		Region:      profile.Region,
	}

	resultJson, err := json.Marshal(result)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "marshal json error: %s", err)
		return
	}

	_, err = w.Write(resultJson)
	if err != nil {
		panic(err)
	}
}

func (s *server) handleSessionToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.ParseForm()

	profileID := r.FormValue("profile_id")
	timeoutMinutesStr := r.Form.Get("timeout_minutes")
	timeout := 10 * time.Minute

	if timeoutMinutesStr != "" {
		timeoutMin, _ := strconv.Atoi(timeoutMinutesStr)
		if timeoutMin > 0 && timeoutMin < 60 {
			timeout = time.Duration(timeoutMin) * time.Minute
		}
	}

	profile, err := s.conf.FindProfile(profileID)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		log.Printf("Profile lookup failed for profile_id=%q, err=%q", r.FormValue("profile_id"), err)
		return
	}

	creds := s.creds[profile.ID]

	if creds == nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "No creds available")
		log.Printf("No creds found for profile=%q", profile.ID)
		return
	}

	if creds.Expiration.Before(time.Now()) {
		w.WriteHeader(400)
		fmt.Fprintf(w, "creds expired: %s", creds.Expiration)
		return
	}

	err = s.confirmUserPresence(r.Context(), fmt.Sprintf("req: session-token\nprofile: %s\ntimeout: %s\n", profile.ID, timeout))
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		log.Printf("Confirm user presence failed")
		return
	}

	token := make([]byte, 32)
	rand.Read(token)

	bypassState := userPresenceTokenBypass{
		expiration: time.Now().Add(timeout),
		token:      token,
	}

	creds.userPresenceTokenBypass = append(creds.userPresenceTokenBypass, bypassState)

	tokenB64 := base64.StdEncoding.EncodeToString(token)
	result := messages.UserPresenceBypassToken{
		Token: tokenB64,
	}

	resultJson, err := json.Marshal(result)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "marshal json error: %s", err)
		return
	}

	_, err = w.Write(resultJson)
	if err != nil {
		panic(err)
	}
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.ParseForm()

	profile, err := s.conf.FindProfile(r.FormValue("profile_id"))
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	cfg, err := s.awsConfig(ctx, profile)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws config error: %s", err)
		return
	}

	oidcService := ssooidc.NewFromConfig(cfg)

	flusher := w.(http.Flusher)

	// Generate PKCE parameters
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "generate code verifier: %s", err)
		return
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Generate state for CSRF protection
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "generate state: %s", err)
		return
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	// Start OAuth callback server
	callbackServer, err := NewOAuthCallbackServer()
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "create callback server: %s", err)
		return
	}
	defer callbackServer.Shutdown()

	callbackServer.Start()
	redirectURI := callbackServer.GetCallbackURL()

	// Register client with authorization code support
	registerInput := &ssooidc.RegisterClientInput{
		ClientName:   aws.String("awsso-agent"),
		ClientType:   aws.String("public"),
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		IssuerUrl:    aws.String(profile.StartUrl),
		RedirectUris: []string{redirectURI},
		Scopes:       []string{"sso:account:access"},
	}

	registerResp, err := oidcService.RegisterClient(ctx, registerInput)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "register client: %s", err)
		return
	}

	region := profile.Region
	if region == "" {
		region = "us-east-1"
	}
	baseURL := fmt.Sprintf("https://oidc.%s.amazonaws.com", region)

	// Build authorization URL
	authURL := BuildAuthorizationURL(
		baseURL,
		*registerResp.ClientId,
		redirectURI,
		state,
		codeChallenge,
		[]string{"sso:account:access"},
	)

	fmt.Fprintf(w, "Opening browser for authorization...\n")
	fmt.Fprintf(w, "If browser doesn't open, visit: %s\n", authURL)
	flusher.Flush()

	// Open browser
	if ok := browser.Open(authURL, profile.BrowserCmd); !ok {
		fmt.Fprintf(w, "Failed to open browser automatically\n")
		flusher.Flush()
	}

	// Wait for callback (5 minute timeout)
	fmt.Fprintf(w, "Waiting for authorization...\n")
	flusher.Flush()

	authCode, returnedState, err := callbackServer.WaitForCode(5 * time.Minute)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "wait for authorization: %s", err)
		return
	}

	// Verify state
	if returnedState != state {
		w.WriteHeader(400)
		fmt.Fprintf(w, "state mismatch: expected %s, got %s", state, returnedState)
		return
	}

	// Exchange authorization code for token
	tokenInput := &ssooidc.CreateTokenInput{
		ClientId:     registerResp.ClientId,
		ClientSecret: registerResp.ClientSecret,
		GrantType:    aws.String(grantTypeAuthCode),
		Code:         aws.String(authCode),
		CodeVerifier: aws.String(codeVerifier),
		RedirectUri:  aws.String(redirectURI),
	}

	tokenResp, err := oidcService.CreateToken(ctx, tokenInput)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "create token: %s", err)
		return
	}

	// Store the token
	tok := ssoToken{
		CreateTokenOutput: *tokenResp,
		Expiration:        time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	s.mu.Lock()
	s.creds[profile.ID] = &tok
	s.mu.Unlock()

	fmt.Fprintf(w, "ok!")
}

// getOIDCCreds gets the device authorized creds necessary to then perform
// user auth. These creds have no access to any resources within an AWS account
// on their own.
func (s *server) getOIDCCreds(ctx context.Context, oidcService *ssooidc.Client, profileID string) (*oidcDeviceCreds, error) {
	f, err := os.Open(config.OIDCCachePath(profileID))
	if err != nil {
		return s.fetchAndCacheNewOIDCCreds(ctx, oidcService, profileID)
	}

	defer f.Close()
	dec := json.NewDecoder(f)
	var creds oidcDeviceCreds
	err = dec.Decode(&creds)
	if err != nil {
		return s.fetchAndCacheNewOIDCCreds(ctx, oidcService, profileID)
	}

	exp := time.Unix(creds.ClientSecretExpiresAt, 0)
	if exp.Before(time.Now()) {
		return s.fetchAndCacheNewOIDCCreds(ctx, oidcService, profileID)
	}

	return &creds, nil
}

func (s *server) fetchAndCacheNewOIDCCreds(ctx context.Context, service *ssooidc.Client, profileID string) (*oidcDeviceCreds, error) {
	resp, err := service.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("awsesh"),
		ClientType: aws.String("public"),
	})
	if err != nil {
		return nil, err
	}
	creds := oidcDeviceCreds{
		ClientID:              *resp.ClientId,
		ClientIDIssuedAt:      resp.ClientIdIssuedAt,
		ClientSecret:          *resp.ClientSecret,
		ClientSecretExpiresAt: resp.ClientSecretExpiresAt,
	}

	f, err := os.Create(config.OIDCCachePath(profileID))
	if err != nil {
		return nil, fmt.Errorf("Create cache file for sso client id err: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	err = enc.Encode(creds)
	if err != nil {
		return nil, fmt.Errorf("Encode json to cache file for sso client id err: %w", err)
	}

	return &creds, nil
}

type oidcDeviceCreds struct {
	ClientID              string `json:"clientId"`
	ClientIDIssuedAt      int64  `json:"clientIdIssuedAt"`
	ClientSecret          string `json:"clientSecret"`
	ClientSecretExpiresAt int64  `json:"clientSecretExpiresAt"`
}

func (s *server) handleListAccountRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.ParseForm()

	profile, err := s.conf.FindProfile(r.FormValue("profile_id"))
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	cred := s.creds[profile.ID]
	if cred == nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "no creds available")
		return
	}

	cfg, err := s.awsConfig(ctx, profile)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws config err: %s", err)
		return
	}

	ssoService := sso.NewFromConfig(cfg)

	var roleResult messages.ListAccountsRolesResult

	acctInput := &sso.ListAccountsInput{
		AccessToken: cred.AccessToken,
	}

	paginator := sso.NewListAccountsPaginator(ssoService, acctInput)
	for paginator.HasMorePages() {
		lao, err := paginator.NextPage(ctx)
		if err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, "list accounts err: %s", err)
			return
		}

		for _, acct := range lao.AccountList {
			roleInput := &sso.ListAccountRolesInput{
				AccessToken: cred.AccessToken,
				AccountId:   acct.AccountId,
			}

			rolePaginator := sso.NewListAccountRolesPaginator(ssoService, roleInput)
			for rolePaginator.HasMorePages() {
				laro, err := rolePaginator.NextPage(ctx)
				if err != nil {
					w.WriteHeader(400)
					fmt.Fprintf(w, "list roles err: %s", err)
					return
				}

				for _, role := range laro.RoleList {
					roleResult.Accounts = append(roleResult.Accounts, messages.Account{
						AccountID:    *acct.AccountId,
						AccountName:  *acct.AccountName,
						AccountEmail: *acct.EmailAddress,
						RoleName:     *role.RoleName,
					})
				}
			}
		}
	}

	json.NewEncoder(w).Encode(roleResult)
}

func (s *server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	var result messages.ListProfilesResult
	for _, p := range s.conf.Profile {
		result.Profiles = append(result.Profiles, messages.Profile{
			ID:       p.ID,
			Region:   p.Region,
			StartUrl: p.StartUrl,
		})
	}

	json.NewEncoder(w).Encode(result)
}

type ssoToken struct {
	ssooidc.CreateTokenOutput
	Expiration time.Time

	userPresenceTokenBypass []userPresenceTokenBypass
}

type userPresenceTokenBypass struct {
	expiration time.Time
	token      []byte
}

// generateCodeVerifier generates a PKCE code verifier (64 characters)
func generateCodeVerifier() (string, error) {
	// Use the same character set as AWS CLI: ASCII letters + digits + '-._~'
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	verifier := make([]byte, 64)
	for i := range verifier {
		// Use crypto/rand for secure random number generation
		n := make([]byte, 1)
		if _, err := rand.Read(n); err != nil {
			return "", err
		}
		verifier[i] = charset[n[0]%byte(len(charset))]
	}
	return string(verifier), nil
}

// generateCodeChallenge generates a PKCE code challenge from a verifier
func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	// Use standard base64 URL encoding (with padding), matching AWS CLI
	return base64.URLEncoding.EncodeToString(h[:])
}

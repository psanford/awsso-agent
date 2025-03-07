package server

import (
	"context"
	"crypto/rand"
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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sso"
	"github.com/aws/aws-sdk-go/service/ssooidc"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/psanford/awsso-agent/browser"
	"github.com/psanford/awsso-agent/client"
	"github.com/psanford/awsso-agent/config"
	"github.com/psanford/awsso-agent/internal/notify"
	"github.com/psanford/awsso-agent/messages"
	"github.com/psanford/awsso-agent/pinentry"
	"github.com/psanford/awsso-agent/u2f"
)

var (
	grantType = "urn:ietf:params:oauth:grant-type:device_code"
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

func (c *server) awsSession(profile config.Profile) (*session.Session, error) {
	return session.NewSession(&aws.Config{
		// LogLevel: aws.LogLevel(aws.LogDebug),
		Region: aws.String(profile.Region),
	})
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
			fmt.Fprintf(w, err.Error())
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

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(profile.Region),
	})
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws new session error: %s", err)
		return
	}

	ssoService := sso.New(sess)
	roleResp, err := ssoService.GetRoleCredentials(&sso.GetRoleCredentialsInput{
		AccessToken: creds.AccessToken,
		AccountId:   &accountID,
		RoleName:    &roleName,
	})
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws get-role-credentials error: %s", err)
		return
	}

	exp := time.UnixMilli(*roleResp.RoleCredentials.Expiration)
	outCreds := sts.Credentials{
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

	sess, err := s.awsSession(profile)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws new session error: %s", err)
		return
	}

	oidcService := ssooidc.New(sess)

	deviceCreds, err := s.getOIDCCreds(oidcService, profile.ID)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "get device oidc creds err: %s", err)
		return
	}

	startAuthResp, err := oidcService.StartDeviceAuthorization(&ssooidc.StartDeviceAuthorizationInput{
		StartUrl:     &profile.StartUrl,
		ClientId:     &deviceCreds.ClientID,
		ClientSecret: &deviceCreds.ClientSecret,
	})
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "start device authorization err: %s", err)
		return
	}

	flusher := w.(http.Flusher)

	fmt.Fprintf(w, "Complete verification at:\n%s\n", *startAuthResp.VerificationUriComplete)
	flusher.Flush()

	ok := browser.Open(*startAuthResp.VerificationUriComplete, profile.BrowserCmd)
	if !ok {
		fmt.Fprintf(w, "Failed to open browser\n")
		flusher.Flush()
	}

	var completedToken *ssooidc.CreateTokenOutput
	timeout := time.After(120 * time.Second)
OUTER:
	for {
		select {
		case <-ctx.Done():
			break OUTER
		case <-timeout:
			break OUTER
		default:
		}

		tokenResp, err := oidcService.CreateToken(&ssooidc.CreateTokenInput{
			ClientId:     &deviceCreds.ClientID,
			ClientSecret: &deviceCreds.ClientSecret,
			DeviceCode:   startAuthResp.DeviceCode,
			GrantType:    &grantType,
		})
		if err == nil {
			completedToken = tokenResp
			break
		}

		time.Sleep(2 * time.Second)
	}

	if completedToken == nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "CreateToken timed out\n")
		return
	}

	tok := ssoToken{
		CreateTokenOutput: *completedToken,
		Expiration:        time.Now().Add(time.Duration(*completedToken.ExpiresIn) * time.Second),
	}

	s.creds[profile.ID] = &tok
	fmt.Fprintf(w, "ok!")
}

// getOIDCCreds gets the device authorized creds necessary to then perform
// user auth. These creds have no access to any resources within an AWS account
// on their own.
func (s *server) getOIDCCreds(oidcService *ssooidc.SSOOIDC, profileID string) (*oidcDeviceCreds, error) {
	f, err := os.Open(config.OIDCCachePath(profileID))
	if err != nil {
		return s.fetchAndCacheNewOIDCCreds(oidcService, profileID)
	}

	defer f.Close()
	dec := json.NewDecoder(f)
	var creds oidcDeviceCreds
	err = dec.Decode(&creds)
	if err != nil {
		return s.fetchAndCacheNewOIDCCreds(oidcService, profileID)
	}

	exp := time.Unix(creds.ClientSecretExpiresAt, 0)
	if exp.Before(time.Now()) {
		return s.fetchAndCacheNewOIDCCreds(oidcService, profileID)
	}

	return &creds, nil
}

func (s *server) fetchAndCacheNewOIDCCreds(service *ssooidc.SSOOIDC, profileID string) (*oidcDeviceCreds, error) {
	resp, err := service.RegisterClient(&ssooidc.RegisterClientInput{
		ClientName: aws.String("awsesh"),
		ClientType: aws.String("public"),
	})
	if err != nil {
		return nil, err
	}
	creds := oidcDeviceCreds{
		ClientID:              *resp.ClientId,
		ClientIDIssuedAt:      *resp.ClientIdIssuedAt,
		ClientSecret:          *resp.ClientSecret,
		ClientSecretExpiresAt: *resp.ClientSecretExpiresAt,
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

	sess, err := s.awsSession(profile)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws new session err: %s", err)
		return
	}

	ssoService := sso.New(sess)

	var roleResult messages.ListAccountsRolesResult

	acctInput := &sso.ListAccountsInput{
		AccessToken: cred.AccessToken,
	}

	err = ssoService.ListAccountsPages(acctInput, func(lao *sso.ListAccountsOutput, b bool) bool {
		for _, acct := range lao.AccountList {
			roleInput := &sso.ListAccountRolesInput{
				AccessToken: cred.AccessToken,
				AccountId:   acct.AccountId,
			}
			err = ssoService.ListAccountRolesPagesWithContext(ctx, roleInput, func(laro *sso.ListAccountRolesOutput, b bool) bool {
				for _, role := range laro.RoleList {
					roleResult.Accounts = append(roleResult.Accounts, messages.Account{
						AccountID:    *acct.AccountId,
						AccountName:  *acct.AccountName,
						AccountEmail: *acct.EmailAddress,
						RoleName:     *role.RoleName,
					})
				}
				return true
			})

			if err != nil {
				w.WriteHeader(400)
				fmt.Fprintf(w, "list roles err: %s", err)
				return false
			}

		}

		return true
	})
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "list accounts err: %s", err)
		return
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

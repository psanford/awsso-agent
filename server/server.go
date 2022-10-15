package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssooidc"
	"github.com/psanford/awsso-agent/browser"
	"github.com/psanford/awsso-agent/client"
	"github.com/psanford/awsso-agent/config"
	"github.com/psanford/awsso-agent/pinentry"
	"github.com/psanford/awsso-agent/u2f"
)

var (
	grantType = "urn:ietf:params:oauth:grant-type:device_code"
)

type server struct {
	creds   map[string]*ssooidc.CreateTokenOutput
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

	return http.Serve(l, s.handler)
}

func New(conf *config.Config) *server {
	s := &server{
		creds: make(map[string]*ssooidc.CreateTokenOutput),
		conf:  conf,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/ping", s.handlePing)
	mux.HandleFunc("/login", s.handleLogin)
	// mux.HandleFunc("/session", s.handleSession)

	s.handler = mux

	return s
}

func (s *server) handlePing(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "pong")
}

func (s *server) confirmUserPresence(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	confirmStop := make(chan struct{})
	verifyResult := make(chan error)

	go func() {
		ok, err := pinentry.Confirm(childCtx, "Tap yubikey to auth")
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

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.ParseForm()

	profile, err := s.conf.FindProfile(r.FormValue("profile_id"))
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(profile.Region),
	})
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws new session error: %s", err)
		return
	}

	oidcService := ssooidc.New(sess)

	deviceCreds, err := s.getOIDCCreds(oidcService)
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

	ok := browser.Open(*startAuthResp.VerificationUriComplete)
	if !ok {
		fmt.Fprintf(w, "Failed to open browser\n")
		fmt.Fprintf(w, "Complete verification at: %s\n", *startAuthResp.VerificationUriComplete)
		flusher := w.(http.Flusher)
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

	s.creds[profile.AccountID] = completedToken
	fmt.Fprintf(w, "ok!")
}

// getOIDCCreds gets the device authorized creds necessary to then perform
// user auth. These creds have no access to any resources within an AWS account
// on their own.
func (s *server) getOIDCCreds(oidcService *ssooidc.SSOOIDC) (*oidcDeviceCreds, error) {
	f, err := os.Open(config.OIDCCachePath())
	if err != nil {
		return s.fetchAndCacheNewOIDCCreds(oidcService)
	}

	defer f.Close()
	dec := json.NewDecoder(f)
	var creds oidcDeviceCreds
	err = dec.Decode(&creds)
	if err != nil {
		return s.fetchAndCacheNewOIDCCreds(oidcService)
	}

	exp := time.Unix(creds.ClientSecretExpiresAt, 0)
	if exp.Before(time.Now()) {
		return s.fetchAndCacheNewOIDCCreds(oidcService)
	}

	return &creds, nil
}

func (s *server) fetchAndCacheNewOIDCCreds(service *ssooidc.SSOOIDC) (*oidcDeviceCreds, error) {
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

	f, err := os.Create(config.OIDCCachePath())
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

package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuthCallbackServer handles the OAuth callback for PKCE flow
type OAuthCallbackServer struct {
	server   *http.Server
	listener net.Listener
	mu       sync.Mutex
	code     string
	state    string
	err      error
	done     chan struct{}
}

// NewOAuthCallbackServer creates a new OAuth callback server
func NewOAuthCallbackServer() (*OAuthCallbackServer, error) {
	// Listen on a random port on localhost
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	srv := &OAuthCallbackServer{
		listener: listener,
		done:     make(chan struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", srv.handleCallback)

	srv.server = &http.Server{
		Handler: mux,
	}

	return srv, nil
}

// GetCallbackURL returns the callback URL for this server
func (s *OAuthCallbackServer) GetCallbackURL() string {
	addr := s.listener.Addr().(*net.TCPAddr)
	return fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", addr.Port)
}

// Start starts the OAuth callback server
func (s *OAuthCallbackServer) Start() {
	go func() {
		if err := s.server.Serve(s.listener); err != http.ErrServerClosed {
			s.mu.Lock()
			s.err = err
			s.mu.Unlock()
			close(s.done)
		}
	}()
}

// WaitForCode waits for the authorization code with a timeout
func (s *OAuthCallbackServer) WaitForCode(timeout time.Duration) (string, string, error) {
	select {
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.err != nil {
			return "", "", s.err
		}
		return s.code, s.state, nil
	case <-time.After(timeout):
		s.Shutdown()
		return "", "", fmt.Errorf("timeout waiting for authorization code")
	}
}

// Shutdown shuts down the OAuth callback server
func (s *OAuthCallbackServer) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *OAuthCallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	query := r.URL.Query()

	s.mu.Lock()
	s.code = query.Get("code")
	s.state = query.Get("state")
	s.err = nil

	if errParam := query.Get("error"); errParam != "" {
		s.err = fmt.Errorf("authorization error: %s - %s", errParam, query.Get("error_description"))
	}
	s.mu.Unlock()

	// Respond to the browser
	w.Header().Set("Content-Type", "text/html")
	if s.err != nil {
		fmt.Fprintf(w, "<html><body><h1>Authorization Error</h1><p>%s</p><p>You can close this window.</p></body></html>", s.err)
	} else {
		fmt.Fprintf(w, "<html><body><h1>Authorization Successful</h1><p>You can close this window and return to the terminal.</p></body></html>")
	}

	// Close the server
	close(s.done)
}

// BuildAuthorizationURL builds the authorization URL for PKCE flow
func BuildAuthorizationURL(baseURL, clientID, redirectURI, state, codeChallenge string, scopes []string) string {
	u, _ := url.Parse(baseURL + "/authorize")

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge_method", "S256")
	// AWS CLI trims the final '=' from the code challenge
	q.Set("code_challenge", strings.TrimSuffix(codeChallenge, "="))

	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	} else {
		q.Set("scope", "sso:account:access")
	}

	u.RawQuery = q.Encode()
	return u.String()
}

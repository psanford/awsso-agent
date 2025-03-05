package config

import (
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/psanford/awsso-agent/messages"
)

type Config struct {
	FidoKeyHandles    []string  `toml:"fido-key-handles"`
	UseTouchID        bool      `toml:"use-touch-id"`
	AllowNoUserVerify bool      `toml:"allow-no-user-verify"`
	Profile           []Profile `toml:"profile"`
}

type Profile struct {
	ID       string `toml:"id"`
	StartUrl string `toml:"start-url"`

	// AWS Region. If empty string, will default to "us-east-1"
	Region string `toml:"region"`

	// Command to open url. Blank defaults to detected browser.
	BrowserCmd []string `toml:"browser-command"`
}

func (c *Config) FindProfile(id string) (Profile, error) {
	if id == "" && len(c.Profile) < 1 {
		return Profile{}, errors.New("no profiles available")
	} else if id == "" {
		return c.Profile[0], nil
	}
	for _, p := range c.Profile {
		if p.ID == id {
			return p, nil
		}
	}
	return Profile{}, errors.New("no profile found matching id")
}

var AWSDefaultRegion = "us-east-1"

func confDir() string {
	confDir, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(confDir, "awsso")
}

func SocketPath() string {
	sockPath := os.Getenv("AWSSO_SOCKET")
	if sockPath != "" {
		return sockPath
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		panic(err)
	}
	dir := filepath.Join(cacheDir, "awsso")
	os.MkdirAll(dir, 0755)

	return filepath.Join(dir, "awsso.control.sock")
}

func tryLoadConfig() (Config, error) {
	confPath := filepath.Join(confDir(), "awsso.toml")
	tml, err := os.ReadFile(confPath)
	if err != nil {
		return Config{}, err
	}
	var conf Config
	err = toml.Unmarshal(tml, &conf)
	if err != nil {
		return conf, err
	}

	if len(conf.FidoKeyHandles) < 1 && !conf.AllowNoUserVerify {
		return conf, fmt.Errorf("no fido-key-handles found in config file, and allow-no-user-verify is false")
	}

	names := make(map[string]struct{})

	for i, p := range conf.Profile {
		if p.ID == "" {
			log.Fatalf("profile idx=%d is missing required id field", i)
		}
		_, exists := names[p.ID]
		if exists {
			log.Fatalf("profile id %q exists multiple times", p.ID)
		}
		names[p.ID] = struct{}{}

		if p.StartUrl == "" {
			log.Fatalf("profile id=%s idx=%d is missing required start-url field", p.ID, i)
		}

		if p.Region == "" {
			p.Region = AWSDefaultRegion
		}
		conf.Profile[i] = p
	}

	return conf, nil
}

func LoadConfig() Config {
	conf, err := tryLoadConfig()
	if err != nil {
		panic(err)
	}
	return conf
}

// OIDCCachePath is the path we store the credentials initially
// registered with AWS pre authentication. These are not user
// credentials and cannot be used by themselves to gain account
// access.
func OIDCCachePath(profileID string) string {
	if profileID == "" {
		c, _ := tryLoadConfig()
		profile, err := c.FindProfile(profileID)
		if err != nil {
			return ""
		}
		profileID = profile.ID
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		panic(err)
	}
	dir := filepath.Join(cacheDir, "awsso")
	os.MkdirAll(dir, 0755)

	return filepath.Join(dir, fmt.Sprintf("awsso.oidc-client.%s.cache", profileID))
}

func AccountCachePath(profileID string) string {
	if profileID == "" {
		c, _ := tryLoadConfig()
		profile, err := c.FindProfile(profileID)
		if err != nil {
			return ""
		}
		profileID = profile.ID
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(cacheDir, "awsso")
	os.MkdirAll(dir, 0755)

	return filepath.Join(dir, fmt.Sprintf("awsso.accts.%s.cache", profileID))
}

func CachedAccounts(profileID string) []messages.Account {
	path := AccountCachePath(profileID)

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []messages.Account

	r := csv.NewReader(f)
	for {
		parts, err := r.Read()
		if err != nil {
			break
		}

		if len(parts) < 4 {
			continue
		}
		out = append(out, messages.Account{
			AccountName:  parts[0],
			AccountID:    parts[1],
			RoleName:     parts[2],
			AccountEmail: parts[3],
		})
	}
	return out
}

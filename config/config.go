package config

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/psanford/awsso-agent/messages"
)

type Config struct {
	FidoKeyHandles []string  `toml:"fido-key-handles"`
	Profile        []Profile `toml:"profile"`
}

type Profile struct {
	ID        string `toml:"id"`
	StartUrl  string `toml:"start-url"`
	AccountID string `toml:"account-id"`

	// AWS Region. If empty string, will default to "us-east-1"
	Region string `toml:"region"`
	// AWS ARN partition. If empty string will default to "aws".
	// Use this for gov and china partitions
	Partition string `toml:"partition"`
}

func (c *Config) FindProfile(id string) (Profile, error) {
	if id == "" {
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
var AWSDefaultPartition = "aws"

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

func LoadConfig() Config {
	confPath := filepath.Join(confDir(), "awsso.toml")
	tml, err := ioutil.ReadFile(confPath)
	if err != nil {
		panic(err)
	}
	var conf Config
	err = toml.Unmarshal(tml, &conf)
	if err != nil {
		panic(err)
	}

	// TODO(psanford): Make this optional
	if len(conf.FidoKeyHandles) < 1 {
		panic(fmt.Sprintf("fido-key-handles not set in config file"))
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
		if p.Partition == "" {
			p.Partition = AWSDefaultPartition
		}
		conf.Profile[i] = p
	}

	return conf
}

// OIDCCachePath is the path we store the credentials initially
// registered with AWS pre authentication. These are not user
// credentials and cannot be used by themselves to gain account
// access.
func OIDCCachePath() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		panic(err)
	}
	dir := filepath.Join(cacheDir, "awsso")
	os.MkdirAll(dir, 0755)

	return filepath.Join(dir, "awsso.cached-oidc-client")
}

func AccountCachePath(profileID string) string {
	if profileID == "" {
		c := LoadConfig()
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

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)

		parts := strings.SplitN(line, " ", 4)
		if len(parts) < 3 {
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

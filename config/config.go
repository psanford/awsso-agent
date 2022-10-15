package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
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

	return conf
}

// SSOCachePath is the path we store the credentials initially
// registered with AWS pre authentication. These are not user
// credentials and cannot be used by themselves to gain account
// access.
func SSOCachePath() string {
	return filepath.Join(confDir(), ".cached-client")
}

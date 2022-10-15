package u2f

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"time"

	"github.com/flynn/hid"
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

var applicationID = "awsso-cli"

func getDevice() (*hid.DeviceInfo, error) {
	devices, err := u2fhid.Devices()
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, errors.New("no U2F tokens found")
	}

	if len(devices) > 1 {
		return nil, errors.New("more than 1 u2f device detected")
	}

	d := devices[0]
	return d, nil
}

func appIDSha() []byte {
	applicationIDSha := sha256.New()
	applicationIDSha.Write([]byte(applicationID))

	return applicationIDSha.Sum(nil)
}

func RegisterDevice() (*RegisterResponse, error) {
	d, err := getDevice()
	if err != nil {
		return nil, err
	}
	dev, err := u2fhid.Open(d)
	if err != nil {
		log.Fatal(err)
	}
	t := u2ftoken.NewToken(dev)

	challenge := make([]byte, 32)
	io.ReadFull(rand.Reader, challenge)

	var res []byte
	log.Println("registering device, tap key to continue")
	for {
		res, err = t.Register(u2ftoken.RegisterRequest{
			Challenge:   challenge,
			Application: appIDSha(),
		})
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			log.Fatal(err)
		}
		break
	}

	parsed, err := parseRegisterResponse(res)
	if err != nil {
		log.Fatalf("Failed to parse u2f registration response: %s", err)
	}
	dev.Close()

	return parsed, nil
}

func VerifyDevice(ctx context.Context, candidateKeyHandles []string) error {
	challenge := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, challenge)
	if err != nil {
		panic(err)
	}

	var (
		rr       RegisterResponse
		req      u2ftoken.AuthenticateRequest
		token    *u2ftoken.Token
		tokenErr error
	)
	for _, keyHandle := range candidateKeyHandles {
		err := rr.Unmarshal(keyHandle)
		if err != nil {
			return err
		}

		req = u2ftoken.AuthenticateRequest{
			Challenge:   challenge,
			Application: appIDSha(),
			KeyHandle:   rr.KeyHandleBytes,
		}

		token, tokenErr = getTokenForKey(req)
		if tokenErr == nil {
			break
		}
	}

	if tokenErr != nil {
		// no matching key found for any key handles
		return tokenErr
	}

	done := ctx.Done()

	io.ReadFull(rand.Reader, challenge)
	log.Println("authenticating, tap key to continue")
	var res *u2ftoken.AuthenticateResponse
	for {
		res, err = token.Authenticate(req)
		if err == u2ftoken.ErrPresenceRequired {
			select {
			case <-done:
				return errors.New("auth canceled")
			default:
			}
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			return err
		}
		break
	}

	isValid := VerifySignature(rr.PublicKey(), challenge, res)
	if isValid {
		return nil
	}

	return errors.New("invalid signature for key(s)")
}

func getTokenForKey(authReq u2ftoken.AuthenticateRequest) (*u2ftoken.Token, error) {
	devices, err := u2fhid.Devices()
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, errors.New("no U2F tokens found")
	}

	for _, d := range devices {
		dev, err := u2fhid.Open(d)
		if err != nil {
			return nil, err
		}
		t := u2ftoken.NewToken(dev)

		challenge := make([]byte, 32)
		io.ReadFull(rand.Reader, challenge)
		if err := t.CheckAuthenticate(authReq); err != nil {
			continue
		}
		return t, nil

	}

	return nil, errors.New("no Device found for keyHandle")
}

type RegisterResponse struct {
	PublicKeyBytes       []byte
	KeyHandleBytes       []byte
	AttestationCertBytes []byte
	SignatureBytes       []byte
}

func (rr *RegisterResponse) MarshalKey() string {
	r2 := *rr
	r2.AttestationCertBytes = nil
	r2.SignatureBytes = nil
	jsonData, err := json.Marshal(r2)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(jsonData)
}

func (rr *RegisterResponse) Unmarshal(data string) error {
	rawJson, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return errors.New("Invalid Key")
	}

	err = json.Unmarshal(rawJson, rr)
	if err != nil {
		return errors.New("Invalid Key")
	}

	if len(rr.PublicKeyBytes) == 0 || len(rr.KeyHandleBytes) == 0 {
		return errors.New("Invalid Key")
	}

	return nil
}

func (rr *RegisterResponse) PublicKey() *ecdsa.PublicKey {
	x, y := elliptic.Unmarshal(elliptic.P256(), rr.PublicKeyBytes)
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
}

func VerifySignature(pub *ecdsa.PublicKey, challenge []byte, authResp *u2ftoken.AuthenticateResponse) bool {
	sha := sha256.New()
	sha.Write(appIDSha())
	sha.Write([]byte{1}) // user presence byte

	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, authResp.Counter)
	sha.Write(counterBytes)
	sha.Write(challenge)

	return ecdsa.VerifyASN1(pub, sha.Sum(nil), authResp.Signature)
}

var invalidRegisterResponseErr = errors.New("invalid register response")

func parseRegisterResponse(d []byte) (*RegisterResponse, error) {
	r := bytes.NewReader(d)

	reserved, _ := r.ReadByte()
	if reserved != 0x05 {
		return nil, invalidRegisterResponseErr
	}

	pubKey := make([]byte, 65)
	_, err := io.ReadFull(r, pubKey)
	if err != nil {
		return nil, invalidRegisterResponseErr
	}

	khLen, err := r.ReadByte()
	if err != nil {
		return nil, invalidRegisterResponseErr
	}

	if khLen < 1 {
		return nil, invalidRegisterResponseErr
	}

	keyHandle := make([]byte, khLen)

	_, err = io.ReadFull(r, keyHandle)
	if err != nil {
		return nil, invalidRegisterResponseErr
	}

	remaining, err := io.ReadAll(r)
	if err != nil {
		return nil, invalidRegisterResponseErr
	}

	if len(remaining) < 73 {
		return nil, invalidRegisterResponseErr
	}

	var rawASN struct {
		Content asn1.RawContent
	}

	rest, err := asn1.Unmarshal(remaining, &rawASN)
	if err != nil {
		return nil, invalidRegisterResponseErr
	}

	rr := RegisterResponse{
		PublicKeyBytes:       pubKey,
		KeyHandleBytes:       keyHandle,
		AttestationCertBytes: rawASN.Content,
		SignatureBytes:       rest,
	}

	return &rr, nil
}

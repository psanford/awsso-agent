package messages

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/service/sts"
)

type Credentials struct {
	*sts.Credentials
	Region string
}

type ListAccountsRolesResult struct {
	Accounts []Account `json:"account"`
}

type Account struct {
	AccountName  string `json:"name"`
	AccountID    string `json:"id"`
	RoleName     string `json:"role"`
	AccountEmail string `json:"email"`
}

func (a *Account) String() string {
	safeName := strings.ReplaceAll(a.AccountName, " ", "-")
	return fmt.Sprintf("%s-%s-%s", safeName, a.AccountID, a.RoleName)
}

type ListProfilesResult struct {
	Profiles []Profile `json:"profiles"`
}

type Profile struct {
	ID       string `json:"id"`
	StartUrl string `json:"start-url"`
	Region   string `json:"region"`
}

type LoginResponse struct {
	Status   string
	Error    string
	LoginURL string
	Result   string
}

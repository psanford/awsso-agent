package messages

import (
	"fmt"

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
	return fmt.Sprintf("%s-%s-%s", a.AccountName, a.AccountID, a.RoleName)
}

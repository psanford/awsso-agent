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
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

func (a *Account) RoleString(role string) string {
	return fmt.Sprintf("%s-%s-%s", a.Name, a.ID, role)
}

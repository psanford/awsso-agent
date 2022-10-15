package messages

import "github.com/aws/aws-sdk-go/service/sts"

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

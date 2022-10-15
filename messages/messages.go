package messages

import "github.com/aws/aws-sdk-go/service/sts"

type Credentials struct {
	*sts.Credentials
	Region string
}

package audit

import "github.com/engity-com/bifroest/pkg/cli/common"

type DecryptionIdentityFilesOpts = common.DecryptionIdentityFilesOpts

type TrustAnchorsOpts struct {
	ExpectedProducerIds []string `flag:"expectedProducerId" placeholder:"<producer-id|auditlogName=producer-id>" description:"Trusted 64-hex producer ID for one auditlog, or <auditlogName>=<producer-id> for multiple."`
}

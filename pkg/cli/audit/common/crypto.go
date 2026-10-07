package common

import (
	. "github.com/engity-com/bifroest/pkg/cli/common"
)

type DecryptionIdentityFilesOpts struct {
	DecryptionIdentityFiles []string `flag:"decryptionIdentityFile" placeholder:"<path>" description:"Private SSH key for decrypting audit records; repeat for multiple keys."`
}

type TrustAnchorsOpts struct {
	ExpectedProducerIds []string `flag:"expectedProducerId" placeholder:"<producer-id|auditlogName=producer-id>" description:"Trusted 64-hex producer ID for one auditlog, or <auditlogName>=<producer-id> for multiple."`
}

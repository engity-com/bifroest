package common

type WithSensitiveOpts struct {
	WithSensitive bool `flag:"with-sensitive" description:"Explicitly include sensitive information."`
}

type RequireFullVerificationOpts struct {
	RequireFull bool `flag:"require-full" description:"Require full verification of encrypted content."`
}

type DecryptionIdentityFilesOpts struct {
	DecryptionIdentityFiles []string `flag:"decryptionIdentityFile" description:"Local private key for encrypted content; repeatable."`
}

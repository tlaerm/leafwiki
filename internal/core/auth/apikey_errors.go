package auth

import "errors"

var ErrAPIKeyNotFound = errors.New("api key not found")
var ErrAPIKeyRevoked = errors.New("api key has been revoked")
var ErrAPIKeyExpired = errors.New("api key has expired")
var ErrAPIKeyShortIDTaken = errors.New("api key short id already taken")
var ErrAPIKeyLimitExceeded = errors.New("api key limit exceeded")
var ErrAPIKeyMalformed = errors.New("api key is malformed")

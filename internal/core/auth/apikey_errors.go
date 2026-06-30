package auth

import "errors"

var ErrAPIKeyNotFound = errors.New("api key not found")
var ErrAPIKeyRevoked = errors.New("api key has been revoked")
var ErrAPIKeyExpired = errors.New("api key has expired")

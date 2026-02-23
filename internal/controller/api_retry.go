package controller

import (
	"errors"
	"fmt"
)

// authError is returned when an API call fails with 401 or 403, signaling that the SID should be invalidated and the operation retried.
type authError struct {
	statusCode int
}

func (e *authError) Error() string {
	return fmt.Sprintf("auth error: HTTP %d", e.statusCode)
}

func newAuthError(statusCode int) error {
	return &authError{statusCode: statusCode}
}

func isAuthError(err error) bool {
	var ae *authError
	return errors.As(err, &ae)
}

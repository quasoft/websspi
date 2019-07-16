package websspi

import (
	"errors"
	"fmt"
	"syscall"
	"time"
)

type sspiAPI struct {
}

func (s *sspiAPI) AcquireCredentialsHandle(principal string) (*CredHandle, *time.Time, error) {
	var principalPtr *uint16
	if principal != "" {
		var err error
		principalPtr, err = syscall.UTF16PtrFromString(principal)
		if err != nil {
			return nil, nil, err
		}
	}
	credentialUsePtr, err := syscall.UTF16PtrFromString(NEGOSSP_NAME)
	if err != nil {
		return nil, nil, err
	}
	var handle CredHandle
	var expiry syscall.Filetime
	status := AcquireCredentialsHandle(
		principalPtr,
		credentialUsePtr,
		SECPKG_CRED_INBOUND,
		nil, // logonId
		nil, // authData
		0,   // getKeyFn
		0,   // getKeyArgument
		&handle,
		&expiry,
	)
	if status != SEC_E_OK {
		return nil, nil, fmt.Errorf("call to AcquireCredentialsHandle failed with code %d", status)
	}
	expiryTime := time.Unix(0, expiry.Nanoseconds())
	return &handle, &expiryTime, nil
}

func (s *sspiAPI) AcceptSecurityContext(token string) error {
	return errors.New("not implemented")
}

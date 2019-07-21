package websspi

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
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

func (s *sspiAPI) AcceptSecurityContext(credential *CredHandle, context *CtxtHandle, input []byte) (newCtx *CtxtHandle, out []byte, exp *time.Time, status SECURITY_STATUS, err error) {
	var inputDesc SecBufferDesc
	var inputBuf SecBuffer
	inputDesc.BuffersCount = 1
	inputDesc.Version = SECBUFFER_VERSION
	inputDesc.Buffers = &inputBuf
	inputBuf.BufferSize = uint32(len(input))
	inputBuf.BufferType = SECBUFFER_TOKEN
	inputBuf.Buffer = &input[0]

	var outputDesc SecBufferDesc
	var outputBuf SecBuffer
	outputDesc.BuffersCount = 1
	outputDesc.Version = SECBUFFER_VERSION
	outputDesc.Buffers = &outputBuf
	outputBuf.BufferSize = 0
	outputBuf.BufferType = SECBUFFER_TOKEN
	outputBuf.Buffer = nil

	var expiry syscall.Filetime
	var contextAttr uint32

	status = AcceptSecurityContext(
		credential,
		context,
		&inputDesc,
		ASC_REQ_ALLOCATE_MEMORY|ASC_REQ_MUTUAL_AUTH, // contextReq uint32,
		SECURITY_NATIVE_DREP,                        // targDataRep uint32,
		newCtx,
		&outputDesc,  // *SecBufferDesc
		&contextAttr, // contextAttr *uint32,
		&expiry,      // *syscall.Filetime
	)
	tm := time.Unix(0, expiry.Nanoseconds())
	exp = &tm
	if status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE {
		// Copy outputBuf.Buffer to out and free the outputBuf.Buffer
		out = make([]byte, outputBuf.BufferSize)
		var bufPtr = uintptr(unsafe.Pointer(outputBuf.Buffer))
		for i := 0; i < len(out); i++ {
			out[i] = *(*byte)(unsafe.Pointer(bufPtr))
			bufPtr++
		}
		freeStatus := FreeContextBuffer(outputBuf.Buffer)
		if freeStatus != SEC_E_OK {
			status = freeStatus
			err = fmt.Errorf("could not free output buffer; FreeContextBuffer() failed with code: %d", freeStatus)
			return
		}
	}
	if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE {
		// TODO: Call CompleteToken?
		if err != nil {
			return
		}
	}
	if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED &&
		status != SEC_I_COMPLETE_NEEDED && status != SEC_I_COMPLETE_AND_CONTINUE {
		err = fmt.Errorf("call to AcceptSecurityContext failed with code %d", status)
		return
	}
	// TODO: Return contextAttr?
	return
}

func (s *sspiAPI) FreeCredentialsHandle(handle *CredHandle) error {
	status := FreeCredentialsHandle(handle)
	if status != SEC_E_OK {
		return fmt.Errorf("call to FreeCredentialsHandle failed with code %d", status)
	}
	return nil
}

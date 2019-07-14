package websspi

import "errors"

type sspiAPI struct {
}

func (s *sspiAPI) AcceptSecurityContext(token string) error {
	return errors.New("not implemented")
}

package models

import (
	"time"
)

type DKIMKey struct {
	ID           string    `gorethink:"id"` // the domain
	DateCreated  time.Time `gorethink:"date_created"`
	DateModified time.Time `gorethink:"date_modified"`
	Owner        string    `gorethink:"owner"`
	Selector     string    `gorethink:"selector"`
	PrivateKey   []byte    `gorethink:"private_key"`
	PublicKey    []byte    `gorethink:"public_key"`
}

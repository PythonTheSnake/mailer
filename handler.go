package main

import (
	"crypto/tls"

	"github.com/bitly/go-nsq"
	r "github.com/dancannon/gorethink"
	"github.com/getsentry/raven-go"
	"github.com/lavab/go-spamc"
)

type handler struct {
	WelcomeMessage string
	Hostname       string
	ReadTimeout    int
	WriteTimeout   int
	DataTimeout    int
	MaxConnections int
	MaxMessageSize int
	MaxRecipients  int

	TLSConfig *tls.Config
	RethinkDB *r.Session
	Producer  *nsq.Producer
	Raven     *raven.Client
	Spam      *spamc.Client
}

func (h *handler) ListenAndServe(addr string) error {
	return nil
}

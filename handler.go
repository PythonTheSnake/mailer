package main

import (
	"crypto/tls"
	"time"

	"github.com/bitly/go-nsq"
	r "github.com/dancannon/gorethink"
	"github.com/getsentry/raven-go"
	"github.com/lavab/go-spamc"
	"github.com/lavab/smtpd"
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

	SMTP *smtpd.Server
}

func (h *handler) ListenAndServe(addr string) error {
	if h.SMTP == nil {
		h.SMTP = &smtpd.Server{
			Hostname:       h.Hostname,
			WelcomeMessage: h.WelcomeMessage,

			ReadTimeout:  time.Second * time.Duration(h.ReadTimeout),
			WriteTimeout: time.Second * time.Duration(h.WriteTimeout),
			DataTimeout:  time.Second * time.Duration(h.DataTimeout),

			MaxConnections: h.MaxConnections,
			MaxMessageSize: h.MaxMessageSize,
			MaxRecipients:  h.MaxRecipients,

			WrapperChain: []smtpd.Wrapper{
				h,
			},
			RecipientChain: []smtpd.Recipient{
				h,
			},
			DeliveryChain: []smtpd.Delivery{
				h,
			},

			TLSConfig: h.TLSConfig,
		}
	}

	return nil
}

func (h *handler) Wrap(x func()) func() {
	return func() {
		h.Raven.CapturePanic(x, nil)
	}
}

func (h *handler) HandleRecipient(next func(conn *smtpd.Connection)) func(conn *smtpd.Connection) {
	return func(conn *smtpd.Connection) {
		next(conn)
	}
}

func (h *handler) HandleDelivery(next func(conn *smtpd.Connection)) func(conn *smtpd.Connection) {
	return func(conn *smtpd.Connection) {
		next(conn)
	}
}

package main

import (
	"bytes"
	"crypto/tls"
	"net/mail"
	"strings"
	"time"

	"github.com/bitly/go-nsq"
	r "github.com/dancannon/gorethink"
	"github.com/dchest/uniuri"
	"github.com/getsentry/raven-go"
	"github.com/lavab/api/models"
	"github.com/lavab/api/utils"
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

type handlerState struct {
	Pairs []*statePair
}

type statePair struct {
	Address *models.Address
	Account *models.Account
}

type stateFile struct {
	Body []byte
}

func (h *handler) HandleRecipient(next func(conn *smtpd.Connection)) func(conn *smtpd.Connection) {
	return func(conn *smtpd.Connection) {
		// Prepare the context
		if conn.Environment == nil {
			conn.Environment = map[string]interface{}{}
		} else {
			if _, ok := conn.Environment["state"]; !ok {
				conn.Environment["state"] = &handlerState{
					Pairs: []*statePair{},
				}
			}
		}
		state := conn.Environment["state"].(*handlerState)

		// Get the last recipient's address
		rawAddr := conn.Envelope.Recipients[len(conn.Envelope.Recipients)-1]

		// Parse it
		addr, err := mail.ParseAddress(rawAddr)
		if err != nil {
			conn.Error(err)
			return
		}

		// Split it and normalize the first part
		parts := strings.Split(addr.Address, ",")
		addr.Address =
			utils.RemoveDots(utils.NormalizeUsername(parts[0])) +
				"@" + parts[1]

		// Fetch address from the database
		cursor, err := r.Table("addresses").Get(addr.Address).Run(h.RethinkDB)
		if err != nil {
			conn.Error(err)
			return
		}
		defer cursor.Close()
		var address *models.Address
		if err := cursor.One(&address); err != nil {
			conn.Error(err)
			return
		}

		// Fetch account from the database
		cursor, err = r.Table("accounts").Get(address.Owner).Run(h.RethinkDB)
		if err != nil {
			conn.Error(err)
			return
		}
		defer cursor.Close()
		var account *models.Account
		if err := cursor.One(&account); err != nil {
			conn.Error(err)
			return
		}

		// Append it to the state
		state.Pairs = append(state.Pairs, &statePair{
			Address: address,
			Account: account,
		})

		next(conn)
	}
}

func (h *handler) HandleDelivery(next func(conn *smtpd.Connection)) func(conn *smtpd.Connection) {
	return func(conn *smtpd.Connection) {
		// Context variables
		var (
			isSpam = false
			ctxID  = uniuri.NewLen(uniuri.UUIDLen)
		)

		// Check in antispam
		spamReply, err := h.Spam.Report(string(conn.Envelope.Data))
		if err == nil {
			log.Printf("[%s] %s", ctxID, spamReply.Code)
			log.Printf("[%s] %s", ctxID, spamReply.Message)
			log.Printf("[%s] %s", ctxID, spamReply.Vars)
		}
		if spamReply.Code == spamc.EX_OK {
			if spam, ok := spamReply.Vars["isSpam"]; ok && spam.(bool) {
				isSpam = true
			}
		}

		// Parse the email
		root, err := ParseEmail(bytes.NewReader(conn.Envelope.Data))
		if err != nil {
			conn.Error(err)
			return
		}

		// Prepare the context
		ctx := &handlerContext{
			ID:   ctxID,
			Root: root,
		}

		// Determine email's kind
		if err := ctx.DetermineKind(); err != nil {
			conn.Error(err)
			return
		}

		// Parse From, To and CC
		if err := ctx.ParseMeta(); err != nil {
			conn.Error(err)
			return
		}

		// Branch out into pgpmime, raw or manifest
		switch kind {
		case "raw":
			if err := ctx.ParseRaw(); err != nil {
				conn.Error(err)
				return
			}
		case "pgpmime":
			if err := ctx.ParsePGP(); err != nil {
				conn.Error(err)
				return
			}
		case "manifest":
			if err := ctx.ParseManifest(); err != nil {
				conn.Error(err)
				return
			}
		}

		// Save per user

		// Branch out again - raw or not

		// Encrypt if raw

		// Write to database

		next(conn)
	}
}

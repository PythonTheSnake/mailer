package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/bitly/go-nsq"
	"github.com/blang/semver"
	r "github.com/dancannon/gorethink"
	"github.com/dchest/uniuri"
	"github.com/eaigner/dkim"
	"github.com/getsentry/raven-go"
	"github.com/hashicorp/golang-lru"
	"github.com/lavab/api/models"
	m2 "github.com/lavab/mailer/models"
	man "github.com/lavab/pgp-manifest-go"
	"golang.org/x/crypto/openpgp"
	"gopkg.in/alexcesaro/quotedprintable.v2"
)

type outbound struct {
	SmtpdAddress string
	DKIM         *lru.Cache
	RethinkDB    *r.Session
	Raven        *raven.Client
}

func (o *outbound) HandleMessage(msg *nsq.Message) error {
	// The passed message is a single string wrapped in quotes
	var id string
	if err := json.Unmarshal(msg.Body, &id); err != nil {
		return err
	}

	// Get the email from database
	cursor, err := r.Table("emails").Get(id).Run(o.RethinkDB)
	if err != nil {
		return err
	}
	defer cursor.Close()
	var email *models.Email
	if err := cursor.One(&email); err != nil {
		return err
	}

	// Send the email
	if err := o.SendEmail(email); err != nil {
		eid := o.Raven.CaptureError(err, map[string]string{
			"id": id,
		})
		stdLogger.Printf("[%s - %s] %s", id, eid, err.Error())
		return err
	}

	return nil
}

func (o *outbound) SendEmail(email *models.Email) error {
	// Various context needed to send the email
	var (
		inReplyTo string
		emailBody = &bytes.Buffer{}
	)

	// Ensure that there's InReplyTo in the email
	if email.InReplyTo != "" {
		inReplyTo = email.InReplyTo
	} else {
		// Get the last received email from the thread
		cursor, err := r.Table("emails").GetAllByIndex("threadStatus", []interface{}{
			email.Thread,
			"received",
		}).Pluck("date_created", "message_id", "from").Filter(func(row r.Term) r.Term {
			return r.Expr(email.To).Contains(row.Field("from"))
		}).OrderBy(
			r.Desc(r.Row.Field("date_created")),
		).Limit(1).Run(o.RethinkDB)
		if err != nil {
			return err
		}
		defer cursor.Close()
		var lastEmail []*models.Email
		if err := cursor.All(&lastEmail); err != nil {
			return err
		}

		// If an email is found, make it inReplyTo
		if len(lastEmail) == 1 {
			inReplyTo = lastEmail[0].MessageID
		}
	}

	// Fetch all files related to the email
	var files []*models.File
	if email.Files != nil && len(email.Files) > 0 {
		cursor, err := r.Table("files").GetAll(r.Args(email.Files)).Run(o.RethinkDB)
		if err != nil {
			return err
		}
		defer cursor.Close()
		if err := cursor.All(&files); err != nil {
			return err
		}
	}

	// Generate an email
	switch email.Kind {
	case "raw":
		if files == nil || len(files) == 0 {
			// Raw email with no attachments
			ctx := &templateInput{
				From:        email.From,
				To:          strings.Join(email.To, ", "),
				MessageID:   email.MessageID,
				InReplyTo:   inReplyTo,
				Subject:     email.Name,
				ContentType: email.ContentType,
				Body:        quotedprintable.EncodeToString([]byte(email.Body)),
				Date:        email.DateCreated.Format(time.RubyDate),
			}

			// Add CC if it's in the email
			if email.CC != nil && len(email.CC) > 0 {
				ctx.Cc = strings.Join(email.CC, ", ")
			}

			if err := unencryptedSingle.Execute(emailBody, ctx); err != nil {
				return err
			}
		} else {
			// Raw email with attachments

			// Prepare files
			ctf := []*templateFile{}
			for _, file := range files {
				ctf = append(ctf, &templateFile{
					ContentType: file.Meta.ContentType(),
					Name:        file.Name,
					Body:        base64.StdEncoding.EncodeToString(file.Body),
				})
			}

			// Generate a context
			ctx := &templateInput{
				From:        email.From,
				To:          strings.Join(email.To, ", "),
				MessageID:   email.MessageID,
				InReplyTo:   inReplyTo,
				Boundary:    uniuri.NewLen(20),
				Subject:     email.Name,
				ContentType: email.ContentType,
				Body:        quotedprintable.EncodeToString([]byte(email.Body)),
				Files:       ctf,
				Date:        email.DateCreated.Format(time.RubyDate),
			}

			// Add CC if it's in the email
			if email.CC != nil && len(email.CC) > 0 {
				ctx.Cc = strings.Join(email.CC, ", ")
			}

			if err := unencryptedMulti.Execute(emailBody, ctx); err != nil {
				return err
			}
		}
	case "pgpmime":
		// PGP/MIME email
		ctx := &templateInput{
			From:        email.From,
			To:          strings.Join(email.To, ", "),
			MessageID:   email.MessageID,
			InReplyTo:   inReplyTo,
			Subject:     email.Name,
			ContentType: email.ContentType,
			Manifest:    email.Manifest,
			Body:        email.Body,
			Date:        email.DateCreated.Format(time.RubyDate),
		}

		// Add CC if it's in the email
		if email.CC != nil && len(email.CC) > 0 {
			ctx.Cc = strings.Join(email.CC, ", ")
		}

		if err := pgpMIMETemplate.Execute(emailBody, ctx); err != nil {
			return err
		}
	case "manifest":
		// Fetch the subject hash from database
		cursor, err := r.Table("threads").Get(email.Thread).Do(func(thread r.Term) r.Term {
			return thread.Field("subject_hash")
		}).Run(o.RethinkDB)
		if err != nil {
			return err
		}
		defer cursor.Close()
		var subjectHash string
		if err := cursor.One(&subjectHash); err != nil {
			return err
		}

		if files == nil || len(files) == 0 {
			// Manifest without attachments
			ctx := &templateInput{
				From:        email.From,
				To:          strings.Join(email.To, ", "),
				MessageID:   email.MessageID,
				InReplyTo:   inReplyTo,
				Subject:     email.Name,
				Boundary1:   uniuri.NewLen(20),
				Boundary2:   uniuri.NewLen(20),
				ID:          email.ID,
				Body:        email.Body,
				Manifest:    email.Manifest,
				SubjectHash: subjectHash,
				Date:        email.DateCreated.Format(time.RubyDate),
			}

			// Add CC if it's in the email
			if email.CC != nil && len(email.CC) > 0 {
				ctx.Cc = strings.Join(email.CC, ", ")
			}

			if err := manifestSingle.Execute(emailBody, ctx); err != nil {
				return err
			}
		} else {
			// Manifest with attachments
			ctf := []*templateFile{}
			for _, file := range files {
				ctf = append(ctf, &templateFile{
					Name: file.Name,
					Body: base64.StdEncoding.EncodeToString(file.Body),
				})
			}

			// Generate a template context
			ctx := &templateInput{
				From:        email.From,
				To:          strings.Join(email.To, ", "),
				MessageID:   email.MessageID,
				InReplyTo:   inReplyTo,
				Subject:     email.Name,
				Boundary1:   uniuri.NewLen(20),
				Boundary2:   uniuri.NewLen(20),
				ID:          email.ID,
				Body:        email.Body,
				Manifest:    email.Manifest,
				SubjectHash: subjectHash,
				Files:       ctf,
				Date:        email.DateCreated.Format(time.RubyDate),
			}

			// Add CC if it's in the email
			if email.CC != nil && len(email.CC) > 0 {
				ctx.Cc = strings.Join(email.CC, ", ")
			}

			if err := manifestMulti.Execute(emailBody, ctx); err != nil {
				return err
			}
		}
	}

	// Replace \n with \r\n in the body
	body := emailBody.Bytes()
	body = bytes.Replace(body, []byte("\n"), []byte("\r\n"), -1)

	// Then parse the from field
	fromAddr, err := mail.ParseAddress(email.From)
	if err != nil {
		return err
	}

	// Sign the email - first get the domain from the from email
	parts := strings.Split(fromAddr.Address, "@")
	if len(parts) == 2 {
		// parts[1] contains the domain name. get the signer
		ds, err := o.getDKIMKey(parts[1])
		if err != nil {
			stdLogger.Printf("[%s] %s", email.ID, err)
		} else {
			// Sign it
			body, err = ds.Sign(body)
			if err != nil {
				return err
			}
		}
	}

	// Relay the email - first generate a recipients slice
	recipients := []string{}
	for _, to := range email.To {
		toa, err := mail.ParseAddress(to)
		if err != nil {
			return err
		}

		recipients = append(recipients, toa.Address)
	}
	if email.CC != nil && len(email.CC) > 0 {
		for _, cc := range email.CC {
			cca, err := mail.ParseAddress(cc)
			if err != nil {
				return err
			}

			recipients = append(recipients, cca.Address)
		}
	}

	// Then send it to smtpd
	if err := smtp.SendMail(o.SmtpdAddress, nil, fromAddr.Address, recipients, body); err != nil {
		return err
	}

	// Branch the execution - if not raw, then just set the status to sent
	if email.Kind != "raw" {
		// Mark the email as sent in DB
		if err := r.Table("emails").Get(email.ID).Update(map[string]interface{}{
			"status": "sent",
		}).Exec(o.RethinkDB); err != nil {
			return err
		}
	} else {
		if err := o.encryptEmail(email, files); err != nil {
			return err
		}
	}

	return nil
}

func (o *outbound) getDKIMKey(domain string) (*dkim.DKIM, error) {
	is, ok := o.DKIM.Get(domain)
	if !ok {
		var ds *dkim.DKIM

		// Load the key from database
		cursor, err := r.Table("dkim_keys").Get(domain).Run(o.RethinkDB)
		if err != nil {
			o.DKIM.Add(domain, ds) // sets to nil casted as a pointer to dkim.DKIM
			return nil, err
		}
		defer cursor.Close()
		var key *m2.DKIMKey
		if err := cursor.One(&key); err != nil {
			o.DKIM.Add(domain, ds) // sets to nil casted as a pointer to dkim.DKIM
			return nil, err
		}

		// Create a new dkim conf
		conf, err := dkim.NewConf(key.ID, key.Selector)
		if err != nil {
			o.DKIM.Add(domain, ds) // sets to nil casted as a pointer to dkim.DKIM
			return nil, err
		}

		// Parse the key
		ds, err = dkim.New(conf, key.PrivateKey)
		if err != nil {
			o.DKIM.Add(domain, ds) // sets to nil casted as a pointer to dkim.DKIM
			return nil, err
		}

		// We have the key, add it to the cache
		o.DKIM.Add(domain, ds)

		return ds, nil
	}

	// Try to cast it as a signer
	ds, ok := is.(*dkim.DKIM)
	if !ok {
		o.DKIM.Remove(domain)
		return o.getDKIMKey(domain)
	}

	return ds, nil
}

func (o *outbound) encryptEmail(email *models.Email, files []*models.File) error {
	// Fetch public_key of account
	cursor, err := r.Table("accounts").Get(email.Owner).Do(func(account r.Term) r.Term {
		return account.Field("public_key")
	}).Run(o.RethinkDB)
	if err != nil {
		return err
	}
	defer cursor.Close()
	var accPublicKey string
	if err := cursor.One(&accPublicKey); err != nil {
		return err
	}

	// Get the key
	var key *models.Key
	if accPublicKey != "" {
		cursor, err = r.Table("keys").Get(accPublicKey).Run(o.RethinkDB)
		if err != nil {
			return err
		}
		defer cursor.Close()
		if err := cursor.One(&key); err != nil {
			return err
		}
	} else {
		cursor, err = r.Table("keys").GetAllByIndex("owner", email.Owner).Run(o.RethinkDB)
		if err != nil {
			return err
		}
		defer cursor.Close()
		var keys []*models.Key
		if err := cursor.All(&keys); err != nil {
			return err
		}

		// Pretty much rng right now :)
		key = keys[0]
	}

	// Parse the key
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key.Key))
	if err != nil {
		return err
	}

	// Prepare a new manifest
	manifest := &man.Manifest{
		Version: semver.Version{
			Major: 1,
		},
		Subject: email.Name,
		Parts:   []*man.Part{},
	}

	// Parse from, to and cc
	manifest.From, err = mail.ParseAddress(email.From)
	if err != nil {
		manifest.From = &mail.Address{
			Address: email.From,
		}
	}
	manifest.To, err = mail.ParseAddressList(strings.Join(email.To, ", "))
	if err != nil {
		manifest.To = []*mail.Address{}
		for _, addr := range email.To {
			manifest.To = append(manifest.To, &mail.Address{
				Address: addr,
			})
		}
	}
	if email.CC != nil && len(email.CC) > 0 {
		manifest.CC, err = mail.ParseAddressList(strings.Join(email.CC, ", "))
		if err != nil {
			manifest.CC = []*mail.Address{}
			for _, addr := range email.CC {
				manifest.CC = append(manifest.CC, &mail.Address{
					Address: addr,
				})
			}
		}
	}

	// Encrypt and hash the body
	encryptedBody, err := encryptAndArmor([]byte(email.Body), keyring)
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(email.Body))

	// Append body to the parts
	manifest.Parts = append(manifest.Parts, &man.Part{
		ID:          "body",
		Hash:        hex.EncodeToString(hash[:]),
		ContentType: email.ContentType,
		Size:        len(email.Body),
	})

	// Encrypt the attachments
	for _, file := range files {
		// Encrypt the attachment
		cipher, err := encryptAndArmor(file.Body, keyring)
		if err != nil {
			return err
		}

		// Hash it
		hash := sha256.Sum256(file.Body)

		// Generate a random ID
		id := uniuri.NewLen(20)

		// Push the attachment into the manifest
		manifest.Parts = append(manifest.Parts, &man.Part{
			ID:          id,
			Hash:        hex.EncodeToString(hash[:]),
			Filename:    file.Name,
			ContentType: file.Meta.ContentType(),
			Size:        len(file.Body),
		})

		// Replace the file in database
		err = r.Table("files").Get(file.ID).Replace(&models.File{
			Resource: models.Resource{
				ID:           file.ID,
				DateCreated:  file.DateCreated,
				DateModified: time.Now(),
				Name:         id + ".pgp",
				Owner:        file.Owner,
			},
			Meta: map[string]interface{}{
				"content_type": "application/pgp-encrypted",
			},
			Body: cipher,
			Tags: file.Tags,
		}).Exec(o.RethinkDB)
		if err != nil {
			return err
		}
	}

	// Encrypt the manifest
	strManifest, err := man.Write(manifest)
	if err != nil {
		return err
	}
	encryptedManifest, err := encryptAndArmor(strManifest, keyring)
	if err != nil {
		return err
	}

	// Replace the email
	err = r.Table("emails").Get(email.ID).Replace(&models.Email{
		Resource: models.Resource{
			ID:           email.ID,
			DateCreated:  email.DateCreated,
			DateModified: time.Now(),
			Name:         "Encrypted message (" + email.ID + ")",
			Owner:        email.Owner,
		},
		MessageID: email.MessageID,
		Kind:      "manifest",
		From:      email.From,
		To:        email.To,
		CC:        email.CC,
		BCC:       email.BCC,
		Files:     email.Files,
		Manifest:  string(encryptedManifest),
		Body:      string(encryptedBody),
		InReplyTo: email.InReplyTo,
		Thread:    email.Thread,
		Status:    "sent",
		Secure:    email.Secure,
	}).Exec(o.RethinkDB)
	if err != nil {
		return err
	}

	return nil
}

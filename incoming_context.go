package main

import (
	"errors"
	"mime"
	"net/mail"
	"strings"
)

type handlerContext struct {
	ID string

	Root *message

	Kind   string
	IsSpam bool

	From        string
	To          []string
	CC          []string
	Attachments []*message

	Subject   string
	Manifest  []byte
	Body      []byte
	Signature *message
}

func (h *handlerContext) DetermineKind() error {
	ct := h.Root.Headers.Get("Content-Type")
	h.Kind = "raw" // Default to raw

	// Signed message
	if strings.HasPrefix(ct, "multipart/signed") {
		// Parse the ct
		_, mp, err := mime.ParseMediaType(ct)
		if err != nil {
			return err
		}

		// It requires a protocol
		if _, ok := mp["protocol"]; !ok {
			return errors.New("No protocol found in multipart/signed")
		}

		// Determine which is which
		var (
			bodyPart *message
			sigPart  *message
		)
		for _, child := range h.Root.Children {
			if strings.HasPrefix(child.Header.Get("content-type"), mp["protocol"]) {
				sigPart = child
			} else {
				bodyPart = child
			}
		}

		// Save the signature
		h.Signature = sigPart

		// Determine what's in the body
		bct := bodyPart.Header.Get("Content-Type")
		if strings.HasPrefix(bct, "multipart/encrypted") {
			// multipart/encrypted is dedicated for PGP/MIME and S/MIME
			h.Kind = "pgpmime"
		} else if strings.HasPrefix(bct, "multipart/mixed") && len(bodyPart.Children) >= 2 {
			// Has manifest? It is an email with a PGP manifest. If not, it's unencrypted.
			for _, child := range bodyPart.Children {
				if strings.HasPrefix(child.Headers.Get("Content-Type"), "application/x-pgp-manifest") {
					h.Kind = "manifest"
					break
				}
			}
		}
	}

	if strings.HasPrefix(ct, "multipart/encrypted") {
		// multipart/encrypted is dedicated for PGP/MIME and S/MIME
		h.Kind = "pgpmime"
	} else if strings.HasPrefix(ct, "multipart/mixed") && len(h.Root.Children) >= 2 {
		// Has manifest? It is an email with a PGP manifest. If not, it's unencrypted.
		for _, child := range h.Root.Children {
			if strings.HasPrefix(child.Headers.Get("Content-Type"), "application/x-pgp-manifest") {
				h.Kind = "manifest"
				break
			}
		}
	}

	return nil
}

func (h *handlerContext) ParseMeta() error {
	var from string
	if fromAddr, err := mail.ParseAddress(h.Root.Headers.Get("from")); err == nil {
		from = fromAddr.String()
	} else {
		from = strings.TrimSpace(h.Root.Headers.Get("from"))
	}
	to := strings.Split(h.Root.Headers.Get("to"), ", ")
	cc := strings.Split(h.Root.Headers.Get("cc"), ", ")
	for i, v := range to {
		to[i] = strings.TrimSpace(v)
	}
	for i, v := range cc {
		cc[i] = strings.TrimSpace(v)
	}
	if len(cc) == 1 && cc[0] == "" {
		cc = nil
	}

	h.From = from
	h.To = to1
	h.CC = cc
	h.Subject = h.Root.Headers.Get("subject")

	return nil
}

func removeFromMessages(data []*message, ids []int) []*message {
	n := len(data)
	i := 0
loop:
	for i < n {
		r := data[i]
		for _, id := range ids {
			if id == r.id {
				data[i] = data[n-1]
				n--
				continue loop
			}
		}
		i++
	}
	return data[0:n]
}

func (h *handlerContext) ParseRaw() error {
	// Hack to allow recursion
	var parseBody func(msg *message) (bool, error)
	parseBody = func(msg *message) (bool, error) {
		// Get the content type and analyze it
		contentType := msg.Headers.Get("Content-Type")
		mediaType, mediaParams, err := mime.ParseMediaType(contentType)
		if err != nil {
			return false, err
		}

		// Loop over children of multipart
		if strings.Contains(mediaType, "multipart/") {
			removed := []int{}

			for i, child := range msg.Children {
				attached, err := parseBody(child)
				if err != nil {
					return false, err
				}

				if attached {
					removed = append(removed, i)
				}

				if err := parseBody(child); err != nil {
					return false, err
				}
			}

			// Remove attachments
			msg.Children = removeFromMessages(msg.Children, removed)
		} else {
			// Attachments have Content-Disposition with value of "attachment"
			contentDisposition := msg.Headers.Get("Content-Disposition")
			if contentDisposition != "" {
				disposition, _, err := mime.ParseMediaType(contentDisposition)
				if err != nil {
					return false, err
				}

				if disposition == "attachment" {
					h.Attachments = append(h.Attachments, msg)
					return true, nil
				}
			}
		}

		return false, nil
	}

	// Parse the body
	if _, err := parseBody(h.Root); err != nil {
		return err
	}

	// Encode the message without attachments
	h.Body = h.Root.Encode()
}

func (h *handlerContext) ParsePGP() error {
	var (
		foundManifest = false
		foundBody     = false
	)

	for _, child := range h.Root.Children {
		if !foundManifest {
			if strings.Index(child.Headers.Get("Content-Type"), "application/pgp-encrypted") != -1 {
				manifest = string(child.Body)
				foundManifest = true
			}
		}

		if !foundBody {
			if strings.Index(child.Headers.Get("Content-Type"), "application/pgp-encrypted") == -1 {
				body = string(child.Body)
				foundBody = true
			}
		}

		if foundManifest && foundBody {
			break
		}
	}
}

func (h *handlerContext) ParseManifest() error {

}

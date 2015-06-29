package mailer

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"

	"github.com/dchest/uniuri"
	"gopkg.in/alexcesaro/quotedprintable.v2"
)

type message struct {
	Headers  mail.Header
	Body     []byte
	Children []*Message
}

func (m *message) Encode() []byte {
	result := &bytes.Buffer{}

	// Write headers
	for k, vv := range headers {
		for _, v := range vv {
			result.WriteString(k)
			result.WriteString(": ")
			result.WriteString(v)
			result.WriteString("\r\n")
		}
	}

	// Start the body
	result.WriteString("\r\n")

	// Get the Content-Type
	contentType := m.Headers.Get("Content-Type")

	// If it starts with multipart, then start writing multipart
	if strings.HasPrefix(contentType, "multipart/") {
		// Generate a new boundary
		boundary := uniuri.NewLen(uniuri.UUIDLen)

		// Write the children
		for _, child := range m.Children {
			// Write the first boundary
			result.WriteString("--")
			result.WriteString(boundary)
			result.WriteString("\r\n")

			// Write the child
			result.Write(child.Encode())
		}

		// End the multipart
		result.WriteString("--")
		result.WriteString(bondary)
		result.WriteString("--\r\n")
	} else {
		// Write the body
		result.Write(m.Body)

		// Write a CRLFne
		result.WriteString("\r\n")
	}

	return result.Bytes()
}

func ParseEmail(input io.Reader) (*message, error) {
	// Create a new mail reader
	r1, err := mail.ReadMessage(input)
	if err != nil {
		return nil, err
	}

	// Allocate an email struct
	message := &Message{}
	message.Headers = r1.Header

	// Default Content-Type is text/plain
	if ct := message.Headers.Get("Content-Type"); ct == "" {
		message.Headers["Content-Type"] = []string{"text/plain"}
	}

	// Determine the content type - fetch it and parse it
	mediaType, params, err := mime.ParseMediaType(message.Headers.Get("content-type"))
	if err != nil {
		return nil, err
	}

	// If the email is not multipart, finish the struct and return
	if !strings.HasPrefix(mediaType, "multipart/") {
		body, err = ioutil.ReadAll(r1.Body)
		if err != nil {
			return nil, err
		}

		cte := strings.ToLower(r1.Header.Get("Content-Transfer-Encoding"))
		switch cte {
		case "base64":
			dst := make([]byte, base64.StdEncoding.DecodedLen(len(message.Body)))
			if _, err := base64.StdEncoding.Decode(dst, message.Body); err != nil {
				return nil, err
			}
			message.Body = dst
		case "quoted-printable":
			dst := make([]byte, quotedprintable.MaxDecodedLen(len(message.Body)))

			if _, err := quotedprintable.Decode(dst, message.Body); err != nil {
				return nil, err
			}
			message.Body = dst
		default:
			message.Body = body
		}

		return message, nil
	}

	// Ensure thet a boundary was passed
	if _, ok := params["boundary"]; !ok {
		return nil, errors.New("Invalid Content-Type (no boundary of a multipart type)")
	}

	// Create a new multipart reader
	r2 := multipart.NewReader(r1.Body, params["boundary"])

	// Parse all children
	for {
		// Get the next part
		part, err := r2.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		// Convert the headers back into a byte slice
		header := []byte{}
		for key, values := range part.Header {
			header = append(header, []byte(key+": "+strings.Join(values, ", "))...)
			header = append(header, '\n')
		}

		// Read the body
		body, err := ioutil.ReadAll(part)
		if err != nil {
			return nil, err
		}

		// Merge headers and body and parse it recursively
		parsed, err := ParseEmail(
			bytes.NewReader(
				append(append(header, '\n'), body...),
			),
		)
		if err != nil {
			return nil, err
		}

		// Put the child into parent struct
		message.Children = append(message.Children, parsed)
	}

	// Return the parsed email
	return message, nil
}

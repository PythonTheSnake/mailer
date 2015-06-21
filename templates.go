package main

import (
	"text/template"
)

type templateInput struct {
	From        string
	To          string
	Cc          string
	MessageID   string
	InReplyTo   string
	ContentType string
	Subject     string
	Date        string
	Body        string
	Boundary    string
	Boundary1   string
	Boundary2   string
	Files       []*templateFile
	Manifest    string
	ID          string
	SubjectHash string
}

type templateFile struct {
	Name        string
	Body        string
	ContentType string
}

var unencryptedSingle = template.Must(template.New("us").Parse(
	`From: {{.From}}
To: {{.To}}{{if ne .Cc ""}}
Cc: {{.Cc}}{{end}}
Message-ID: <{{.MessageID}}>{{if ne .InReplyTo ""}}
In-Reply-To: <{{.InReplyTo}}>
References: <{{.InReplyTo}}>{{end}}
Content-Type: {{.ContentType}}
Subject: {{.Subject}}
Date: {{.Date}}
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable

{{.Body}}
`,
))

var unencryptedMulti = template.Must(template.New("um").Parse(
	`From: {{.From}}
To: {{.To}}{{if ne .Cc ""}}
Cc: {{.Cc}}{{end}}
Message-ID: <{{.MessageID}}>{{if ne .InReplyTo ""}}
In-Reply-To: <{{.InReplyTo}}>
References: <{{.InReplyTo}}>{{end}}
Content-Type: multipart/mixed; boundary="{{.Boundary}}"
Subject: {{.Subject}}
Date: {{.Date}}
MIME-Version: 1.0

--{{.Boundary}}
Content-Type: {{.ContentType}}
Content-Transfer-Encoding: quoted-printable

{{.Body}}
{{ range .Files }}
--{{$.Boundary}}
Content-Type: {{.ContentType}}
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="{{.Name}}"

{{.Body}}
{{end}}
--{{.Boundary}}--
`,
))

var pgpMIMETemplate = template.Must(template.New("pm").Parse(
	`From: {{.From}}
To: {{.To}}{{if ne .Cc ""}}
Cc: {{.Cc}}{{end}}
Message-ID: <{{.MessageID}}>{{if ne .InReplyTo ""}}
In-Reply-To: <{{.InReplyTo}}>
References: <{{.InReplyTo}}>{{end}}
Content-Type: multipart/encrypted;
              protocol="application/pgp-encrypted";
              boundary="{{.Boundary}}"
Subject: {{.Subject}}
Date: {{.Date}}
MIME-Version: 1.0

--{{.Boundary}}
Content-Type: application/pgp-encrypted
Content-Disposition: attachment

{{.Manifest}}

--{{.Boundary}}
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="msg.asc"

{{.Body}}
--{{.Boundary}}--
`,
))

var manifestSingle = template.Must(template.New("ms").Parse(
	`From: {{.From}}
To: {{.To}}{{if ne .Cc ""}}
Cc: {{.Cc}}{{end}}
Message-ID: <{{.MessageID}}>{{if ne .InReplyTo ""}}
In-Reply-To: <{{.InReplyTo}}>
References: <{{.InReplyTo}}>{{end}}
Content-Type: multipart/mixed; boundary="{{.Boundary1}}"
Subject: {{.Subject}}
Subject-Hash: {{.SubjectHash}}
Date: {{.Date}}
MIME-Version: 1.0

--{{.Boundary1}}
Content-Type: multipart/alternative; boundary="{{.Boundary2}}"

--{{.Boundary2}}
Content-Type: application/pgp-encrypted

{{.Body}}
--{{.Boundary2}}
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body>
<p>This is an encrypted email, <a href="https://view.lavaboom.com/#{{.ID}}">
open it here if you email client doesn't support PGP manifests
</a></p>
</body>
</html>
--{{.Boundary2}}
Content-Type: text/plain; charset="UTF-8"

This is an encrypted email, open it here if your email client
doesn't support PGP manifests:
https://view.lavaboom.com/#{{.ID}}
--{{.Boundary2}}--
--{{.Boundary1}}
Content-Type: application/x-pgp-manifest+json
Content-Disposition: attachment; filename="manifest.pgp"

{{.Manifest}}
--{{.Boundary1}}--
`))

var manifestMulti = template.Must(template.New("mm").Parse(
	`From: {{.From}}
To: {{.To}}{{if ne .Cc ""}}
Cc: {{.Cc}}{{end}}
Message-ID: <{{.MessageID}}>{{if ne .InReplyTo ""}}
In-Reply-To: <{{.InReplyTo}}>
References: <{{.InReplyTo}}>{{end}}
Content-Type: multipart/mixed; boundary="{{.Boundary1}}"
Subject: {{.Subject}}
Subject-Hash: {{.SubjectHash}}
Date: {{.Date}}
MIME-Version: 1.0

--{{.Boundary1}}
Content-Type: multipart/alternative; boundary="{{.Boundary2}}"

--{{.Boundary2}}
Content-Type: application/pgp-encrypted

{{.Body}}
--{{.Boundary2}}
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body>
<p>This is an encrypted email, <a href="https://view.lavaboom.com/#{{.ID}}">
open it here if you email client doesn't support PGP manifests
</a></p>
</body>
</html>
--{{.Boundary2}}
Content-Type: text/plain; charset="UTF-8"

This is an encrypted email, open it here if your email client
doesn't support PGP manifests:
https://view.lavaboom.com/#{{.ID}}
--{{.Boundary2}}--{{ range .Files }}
--{{$.Boundary1}}
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="{{.Name}}"

{{.Body}}
{{ end }}
--{{.Boundary1}}
Content-Type: application/x-pgp-manifest+json
Content-Disposition: attachment; filename="manifest.pgp"

{{.Manifest}}
--{{.Boundary1}}--`,
))

package main

type handlerContext struct {
	ID string

	Root *message

	Kind   string
	From   string
	IsSpam bool
	To     []string
	CC     []string
}

func (h *handlerContext) DetermineKind() error {
	ct := h.Root.Headers.Get("Content-Type")
	h.Kind = "raw" // Default to raw
	if strings.HasPrefix(ct, "multipart/encrypted") {
		// multipart/encrypted is dedicated for PGP/MIME and S/MIME
		h.Kind = "pgpmime"
	} else if strings.HasPrefix(ct, "multipart/mixed") && len(email.Children) >= 2 {
		// Has manifest? It is an email with a PGP manifest. If not, it's unencrypted.
		for _, child := range root.Children {
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
	if fromAddr, err := mail.ParseAddress(root.Headers.Get("from")); err == nil {
		from = fromAddr.String()
	} else {
		from = strings.TrimSpace(root.Headers.Get("from"))
	}
	to := strings.Split(email.Headers.Get("to"), ", ")
	cc := strings.Split(email.Headers.Get("cc"), ", ")
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
	return nil
}

func (h *handlerContext) ParseRaw() error {

}

func (h *handlerContext) ParsePGP() error {

}

func (h *handlerContext) ParseManifest() error {

}

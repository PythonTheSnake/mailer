package main

import (
	"errors"
	"fmt"

	"github.com/getsentry/raven-go"
)

func capturePanic(rc *raven.Client) {
	var packet *raven.Packet
	p := recover()
	switch rval := p.(type) {
	case nil:
		return
	case error:
		packet = raven.NewPacket(rval.Error(), raven.NewException(rval, raven.NewStacktrace(2, 3, nil)))
	default:
		rvalStr := fmt.Sprint(rval)
		packet = raven.NewPacket(rvalStr, raven.NewException(errors.New(rvalStr), raven.NewStacktrace(2, 3, nil)))
	}

	_, ch := rc.Capture(packet, nil)
	<-ch
}

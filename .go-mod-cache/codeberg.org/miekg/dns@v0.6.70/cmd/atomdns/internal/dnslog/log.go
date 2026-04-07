package dnslog

import (
	"context"
	"log/slog"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
)

func PackFail(ctx context.Context, log *slog.Logger, err slog.Attr) {
	const packFail = "Pack failure"
	log.With(dnsctx.Id(ctx)).Debug(packFail, err)
}

// GroupValues returns all elements in values as slog.Attr, for loging as slog.GroupValue.
func GroupValues(key string, values []string) []slog.Attr {
	attrs := make([]slog.Attr, len(values))
	for i := range values {
		attrs[i] = slog.String(key, values[i])
	}
	return attrs
}

func Error(err error) slog.Attr { return slog.Any("error", err) }

package handlers

import (
	"io"
	"log/slog"
)

func safeClose(c io.Closer, label string) {
	if err := c.Close(); err != nil {
		slog.Debug("close error", "resource", label, "error", err)
	}
}

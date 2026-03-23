package logger

import (
	"log/slog"
	"os"
)

// Log is the package-level structured logger. It is initialised to a no-op
// handler by default so callers can safely use it before Init is called.
var Log *slog.Logger

func init() {
	// Default: discard all messages until Init is called.
	Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// Init configures the package-level logger.
//   - logFile != "": write JSON logs to that file (creates/appends).
//   - verbose:        text handler at DEBUG level on stderr.
//   - otherwise:      text handler at INFO level on stderr.
func Init(verbose bool, logFile string) {
	var handler slog.Handler
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			// Fall back to stderr text handler and log the open error.
			handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
			Log = slog.New(handler)
			Log.Error("logger: could not open log file, falling back to stderr", "path", logFile, "err", err)
			return
		}
		handler = slog.NewJSONHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug})
	} else if verbose {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	} else {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	Log = slog.New(handler)
}

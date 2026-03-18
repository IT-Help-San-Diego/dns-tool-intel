// dns-tool:scrutiny plumbing
package logging

import (
        "io"
        "log/slog"
        "os"

        "github.com/jackc/pgx/v5/pgxpool"
)

type Logger struct {
        FileWriter *RotatingFileWriter
        DBSink     *DBSink
        Discord    *DiscordSink
}

func Setup(pool *pgxpool.Pool, discordWebhookURL string) (*Logger, error) {
        logDir := "logs"
        if dir := os.Getenv("LOG_DIR"); dir != "" {
                logDir = dir
        }

        fileWriter, err := NewRotatingFileWriter(logDir, "dnstool")
        if err != nil {
                return nil, err
        }

        var dbSink *DBSink
        if pool != nil {
                dbSink = NewDBSink(pool)
        }

        var discordSink *DiscordSink
        if discordWebhookURL != "" {
                discordSink = NewDiscordSink(discordWebhookURL, slog.LevelWarn)
        }

        combined := io.MultiWriter(os.Stdout, fileWriter)

        handler := NewMultiHandler(Config{
                FileWriter:  combined,
                DBSink:      dbSink,
                DiscordSink: discordSink,
                MinLevel:    slog.LevelDebug,
        })

        slog.SetDefault(slog.New(handler))

        return &Logger{
                FileWriter: fileWriter,
                DBSink:     dbSink,
                Discord:    discordSink,
        }, nil
}

func (l *Logger) Close() {
        if l.FileWriter != nil {
                l.FileWriter.Close()
        }
        if l.DBSink != nil {
                l.DBSink.Close()
        }
}

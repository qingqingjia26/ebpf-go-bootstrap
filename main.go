package main

import (
	"log/slog"
	"os"
)

var opts = slog.HandlerOptions{
	AddSource: false,
	Level:     slog.LevelDebug,
}

func main() {

	slog.Debug("debug before setting")
	slog.Info("info before setting")

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &opts)))
	slog.Debug("debug after setting")
	slog.Info("info after setting")

	opts.Level = slog.LevelInfo
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &opts)))
	slog.Debug("debug after setting Level to Info")
	slog.Info("info after setting Level to Info")
}

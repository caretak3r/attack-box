package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"attackbox/internal/hostevidence"
	"attackbox/internal/telemetry"
)

func main() {
	source := flag.String("source", "", "falco or journal")
	stateDir := flag.String("state-dir", "", "private durable cursor directory")
	socket := flag.String("socket", "", "host receipt socket")
	file := flag.String("file", "/var/log/falco-events.jsonl", "Falco JSONL source")
	flag.Parse()
	if (*source != "falco" && *source != "journal") || *stateDir == "" {
		log.Fatal("source and state-dir required")
	}
	if err := telemetry.ValidSocketPath(*socket); err != nil {
		log.Fatal(err)
	}
	state, err := hostevidence.OpenState(*stateDir, *source)
	if err != nil {
		log.Fatal(err)
	}
	defer state.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sender := hostevidence.Sender{Socket: *socket, Role: "runtime"}
	if *source == "journal" {
		sender.Role = "egress"
		err = hostevidence.RunJournal(ctx, state, sender)
	} else {
		err = hostevidence.RunFile(ctx, state, *file, sender)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Print(err)
		os.Exit(1)
	}
}

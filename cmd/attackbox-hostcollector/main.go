package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"attackbox/internal/hostcollector"
)

func main() {
	snapshot := flag.Bool("snapshot", false, "collect fixed privileged inventory and exit")
	stdout := flag.Bool("snapshot-stdout", false, "print fixed privileged inventory without file writes")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *snapshot && *stdout {
		log.Fatal("snapshot modes are mutually exclusive")
	}
	if *snapshot || *stdout {
		if os.Geteuid() != 0 {
			log.Fatal("snapshot requires root")
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		s := hostcollector.Collect(ctx)
		if *stdout {
			if err := json.NewEncoder(os.Stdout).Encode(s); err != nil {
				log.Fatal(err)
			}
			return
		}
		if err := hostcollector.WriteSnapshot(s); err != nil {
			log.Fatal(err)
		}
		return
	}
	if os.Geteuid() == 0 {
		log.Fatal("HTTP collector must run unprivileged")
	}
	c := hostcollector.New()
	listener, err := hostcollector.Listen()
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: c, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	go c.Run(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

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
	loop := flag.Bool("snapshot-loop", false, "refresh privileged inventory every 60 seconds")
	stdout := flag.Bool("snapshot-stdout", false, "print fixed privileged inventory without file writes")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if (*snapshot && *stdout) || (*loop && (*snapshot || *stdout)) {
		log.Fatal("snapshot modes are mutually exclusive")
	}
	if *snapshot || *stdout || *loop {
		if os.Geteuid() != 0 {
			log.Fatal("snapshot requires root")
		}
		if *loop {
			for ctx.Err() == nil {
				run, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := hostcollector.WriteSnapshot(hostcollector.Collect(run))
				cancel()
				if err != nil {
					log.Print(err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(60 * time.Second):
				}
			}
			return
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

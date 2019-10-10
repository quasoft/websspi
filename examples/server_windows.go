package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quasoft/websspi"
)

func main() {
	config := websspi.NewConfig()
	auth, err := websspi.New(config)
	if err != nil {
		panic(err)
	}

	server := &http.Server{Addr: "0.0.0.0:9000"}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := ""
		w.Write([]byte("Hello " + username))
	})
	http.Handle("/", auth.WithAuth(handler))

	stop := make(chan os.Signal, 2)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %s\n", err)
		}
	}()

	// Wait for SIGINT or SIGTERM
	<-stop
	log.Print("Shutting down and releasing resources...\n")
	err = auth.Free()
	if err != nil {
		log.Printf("Error while releasing resources: %v\n", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Graceful shutdown timed out: %s\n", err)
	}
}

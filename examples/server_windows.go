package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quasoft/websspi"
)

var helloTemplate = template.Must(template.New("index.html").Parse(`
{{- if .User -}}
<h2>Hello {{ .User.Username }}!</h2>

{{ if .User.Groups -}}
Groups:
<ul>
{{- range .User.Groups}}
	<li>{{ . }}</li>
{{end -}}
</ul>
{{- if .Linked}}
<h3>Linked Token: {{ .Linked.Username }}</h3>
Groups:
<ul>
{{- range .Linked.Groups}}
	<li>{{ . }}</li>
{{end -}}
</ul>
{{end -}}
{{- end }}
{{- else -}}
<h2>Hello!</h2>
{{- end -}}
`))

func main() {
	config := websspi.NewConfig()
	config.EnumerateGroups = true // If groups should be resolved
	// config.ServerName = "..." // If static instead of dynamic group membership should be resolved
	config.ResolveLinked = true
	// If a linked token should be resolved.
	// For UAC restricted admin the linked user info will have the "all" groups.
	// For UAC elevated user the linked user info will have the restricted ones.

	auth, err := websspi.New(config)
	if err != nil {
		panic(err)
	}

	server := &http.Server{Addr: "0.0.0.0:9000"}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := r.Context().Value(websspi.UserInfoKey)
		linked := r.Context().Value(websspi.LinkedTokenUserInfoKey)
		userInfo, _ := info.(*websspi.UserInfo)
		linkedTokenUserInfo, _ := linked.(*websspi.UserInfo)
		w.Header().Add("Content-Type", "text/html; encoding=utf-8")
		helloTemplate.Execute(w, struct {
			User   *websspi.UserInfo
			Linked *websspi.UserInfo
		}{
			userInfo, linkedTokenUserInfo,
		})
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

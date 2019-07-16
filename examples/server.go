package main

import (
	"log"
	"net/http"

	"github.com/quasoft/websspi"
)

func main() {
	config := websspi.NewConfig()
	auth, err := websspi.New(config)
	if err != nil {
		panic(err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := ""
		w.Write([]byte("Hello " + username))
	})
	http.Handle("/", auth.WithAuth(handler))

	log.Fatal(http.ListenAndServe("0.0.0.0:9000", nil))
}

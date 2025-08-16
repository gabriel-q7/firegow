package backend

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Backend received: %s %s\n", r.Method, r.URL.Path)
		fmt.Fprintf(w, "Headers: %v\n", r.Header)
	})

	fmt.Println("Test backend running on :8081")
	http.ListenAndServe(":8081", nil)
}

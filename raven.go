package main

/*
	Raven is a service that will call out to Troy Hunt's PwnedPassword API v2.
	In V2, the steps used is to first use SHA-1 to hash the password on the client side.
	Then take the first five characters and hit the PwnedPassword API. With the list of
	returned shortened hashes, we compare the rest of the characters in the SHA-1 hashed
	password and return the count.
	If the password is not found, the count will be 0.
*/
import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

type Hasher struct {
	SHA hash.Hash
}

type PasswordDealer interface {
	HashPassword(word string) []byte
}

type Handler struct {
	Hasher PasswordDealer
	Client *http.Client
}

type Response struct {
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

func main() {

	hasher := Hasher{
		SHA: sha1.New(),
	}

	h := Handler{
		Client: &http.Client{},
		Hasher: &hasher,
	}

	r := mux.NewRouter()
	r.HandleFunc("/password/{password}", h.CheckPasswordHandler)
	http.Handle("/", r)

	fmt.Println("api listening on port 8080...")
	if http.ListenAndServe(":8080", nil) != nil {
		panic("what")
	}
}

func (h *Handler) CheckPasswordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	p := vars["password"]
	if p == "" {
		WriteJSON(w, Response{Count: 0, Error: "no password provided"}, http.StatusBadRequest)
		return
	}

	pwd := h.Hasher.HashPassword(p)

	foundhash, count, err := h.CompareHashes(pwd)
	if err != nil {
		WriteJSON(w, Response{Count: 0, Error: err.Error()}, http.StatusInternalServerError)
		return
	}

	if foundhash == "" {
		WriteJSON(w, Response{Count: 0}, http.StatusOK)
		return
	}

	c, _ := strconv.Atoi(count)
	WriteJSON(w, Response{Count: c}, http.StatusOK)
}

func (hasher *Hasher) HashPassword(word string) []byte {
	sha := sha1.New()
	io.WriteString(sha, word)
	return sha.Sum(nil)
}

func (h *Handler) CompareHashes(hash []byte) (string, string, error) {
	b16 := fmt.Sprintf("%x", hash)

	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", b16[:5])
	resp, err := h.Client.Get(url)
	if err != nil {
		return "", "", err
	}

	var lines []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanner.Err() != nil {
		return "", "", scanner.Err()
	}

	for _, line := range lines {
		k := strings.Split(line, ":")
		if k[0] == strings.ToUpper(b16[5:]) {
			return k[0], k[1], nil
		}
	}

	return "", "", nil
}

func WriteJSON(w http.ResponseWriter, data interface{}, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/gorilla/mux"
)

var jwtKey = []byte("secret-key")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var usersData = map[string]string{
	"John":  "jpwd",
	"Alice": "apwd",
}

type Token struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/signin", signin).Methods("POST")
	router.HandleFunc("/user", dashboard).Methods("GET")

	fmt.Println("Starting server on the port 8080...")
	log.Fatal(http.ListenAndServe(":8080", router))

}

func signin(w http.ResponseWriter, req *http.Request) {
	var creds Credentials

	err := json.NewDecoder(req.Body).Decode(&creds) //reads what values was sent from request
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Can not decode by Signing in"))
		return
	}

	userPassword, ok := usersData[creds.Username]

	if !ok || userPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf(`{"message":"credetials are not correct"}`)))
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	tokenClaim := Token{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaim)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(tokenString)

	cookie, err := req.Cookie("token")
	if err != nil {
		fmt.Println("cookie:", cookie, "err:", err)
		cookie := &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		}
		http.SetCookie(w, cookie)
		fmt.Println("cookie:", cookie, "err:", err)
	}

	w.Header().Set("Content-Type", "application/json")

	w.Write([]byte(fmt.Sprintf(`{"token":"%s"}`, tokenString)))

}

func dashboard(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	bearerToken := req.Header.Get("Authorization")
	token, err := ValidateToken(bearerToken)

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	user := token.Claims.(*Token)
	json.NewEncoder(w).Encode(fmt.Sprintf("%s's Dashboard", user.Username))
}

func ValidateToken(bearerToken string) (*jwt.Token, error) {
	tokenString := strings.Split(bearerToken, " ")[1]
	token, err := jwt.ParseWithClaims(tokenString, &Token{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	return token, err
}

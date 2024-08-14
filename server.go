package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Структура для хранения сессии;
type Session struct {
	SessionID string    `json: "session_id"`
	Expiry    time.Time `json: "expiry"`
}

var session = make(map[string]Session)

const (
	storedLogin    = "user123"
	storedPassword = "pass456"
)

// Функция входящей информации;
type LogDataJS struct {
	Login    string `json: "login"`
	Password string `json: "password"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	data := LogDataJS{}

	// Декодирование JSON из тела запроса;
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Сравнение полученных логина и пароля с заранее определёнными;
	if data.Login == storedLogin && data.Password == storedPassword {
		fmt.Fprintf(w, "Успешный вход: %s", data.Login)

		// Генерация UUID для сессии
		sessionID := uuid.New().String()
		expiry := time.Now().Add(2 * time.Minute)

		session := Session{
			SessionID: sessionID,
			Expiry:    expiry,
		}
		// Возвращаем сессию в формате JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(session)
	} else {
		http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
	}
}

// Middleware для проверки сессии
func sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get("Session-ID")
		if sessionID == "" {
			http.Error(w, "Session-ID header is missing", http.StatusUnauthorized)
			return
		}

		if sessionID != "valid-session-id" { // Замените на реальную проверку
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Вы получили доступ к защищенному ресурсу!")
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/log", loginHandler)
	mux.Handle("/protected", sessionMiddleware(http.HandlerFunc(protectedHandler)))

	http.ListenAndServe(":8080", mux)
}

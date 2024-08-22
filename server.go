package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"

	_ "github.com/lib/pq"
)

// Структура для хранения данных пользователя
type User struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Структура для хранения сессии;
type Session struct {
	SessionID string    `json:"session_id"`
	Expiry    time.Time `json:"expiry"`
}

var db *sql.DB
var session = make(map[string]Session)

func InitializeDataBase() {
	var err error
	connStr := "user=postgres password=pgpwd4habr dbname=postgres sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
}

// Хеширование пароля
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Проверка пароля
func checkPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func registrHandler(w http.ResponseWriter, r *http.Request) {
	var regUser User
	err := json.NewDecoder(r.Body).Decode(&regUser)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hashedPassword, err := hashPassword(regUser.Password)
	_, err = db.Exec("INSERT INTO logdata (login, hashed_pas) VALUES ($1, $2)", regUser.Login, hashedPassword)
	if err != nil {
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var storedPassword string
	err = db.QueryRow("SELECT hashed_pas FROM logdata WHERE login=$1", user.Login).Scan(&storedPassword)
	if err != nil || checkPasswordHash(user.Password, storedPassword) != nil {
		http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
		return
	} else {
		// Генерация UUID для сессии
		sessionID := uuid.New().String()
		expiry := time.Now().Add(2 * time.Minute)

		session := Session{
			SessionID: sessionID,
			Expiry:    expiry,
		}

		// Сохранение сессии в базе данных (не забудьте добавить поле user_id в таблицу sessions)
		_, err = db.Exec("INSERT INTO sessions (uuid, user_id) VALUES ($1, $2)", sessionID, "1")
		if err != nil {
			http.Error(w, "Could not create session", http.StatusInternalServerError)
			return
		}
		// Возвращаем сессию в формате JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(session)
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

		// Проверка существования сессии в базе данных
		var userID string
		err := db.QueryRow("SELECT uuid FROM sessions WHERE user_id=$1", "1").Scan(&userID)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Добавляем userID в контекст
		ctx := context.WithValue(r.Context(), "userID", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)
	// Создаем ответ в формате JSON
	response := map[string]string{
		"message": fmt.Sprintf("Welcome, %s!", userID),
	}

	// Устанавливаем заголовок Content-Type
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // Устанавливаем статус 200 OK

	// Кодируем ответ в JSON и отправляем его клиенту
	json.NewEncoder(w).Encode(response)
}

func main() {
	InitializeDataBase()

	r := mux.NewRouter()

	r.HandleFunc("/reg", registrHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")

	// Применяем middleware к защищенному маршруту
	r.Handle("/protected", sessionMiddleware(http.HandlerFunc(protectedHandler))).Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", r))
}

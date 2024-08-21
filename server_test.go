package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/lib/pq"
)

func setupTestDB() (*sql.DB, error) {
	connStr := "user=postgres password=pgpwd4habr dbname=postgres sslmode=disable"
	return sql.Open("postgres", connStr)
}

func TestLoginHandler_Success(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Создаем тестового пользователя в базе данных
	_, err = db.Exec("INSERT INTO logdata (login, password, user_id) VALUES ($1, $2, $3)", "testuser", "testpass", "testid")
	if err != nil {
		t.Fatal(err)
	}

	user := User{Username: "testuser", Password: "testpass"}
	body, _ := json.Marshal(user)

	req, err := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(loginHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	var session Session
	if err := json.NewDecoder(rr.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}

	if session.SessionID == "" {
		t.Error("Expected a session ID, got empty string")
	}
}

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	user := User{Username: "invaliduser", Password: "invalidpass"}
	body, _ := json.Marshal(user)

	req, err := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(loginHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

func TestSessionMiddleware_Success(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sessionID := "test-session-id"
	_, err = db.Exec("INSERT INTO sessions (uuid) VALUES ($1)", sessionID)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Session-ID", sessionID)

	rr := httptest.NewRecorder()
	handler := sessionMiddleware(http.HandlerFunc(protectedHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestSessionMiddleware_MissingSessionID(t *testing.T) {
	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := sessionMiddleware(http.HandlerFunc(protectedHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

func TestSessionMiddleware_InvalidSessionID(t *testing.T) {
	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Session-ID", "invalid-session-id")

	rr := httptest.NewRecorder()
	handler := sessionMiddleware(http.HandlerFunc(protectedHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

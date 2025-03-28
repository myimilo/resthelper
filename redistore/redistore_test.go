package redistore

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/zeromicro/go-zero/core/stores/redis"
)

const (
	defaultRedisHost = "127.0.0.1"
	defaultRedisPort = "6379"
)

func setupRedis() *redis.Redis {
	addr := os.Getenv("REDIS_HOST")
	if addr == "" {
		addr = defaultRedisHost
	}

	port := os.Getenv("REDIS_PORT")
	if port == "" {
		port = defaultRedisPort
	}

	pass := os.Getenv("REDIS_PASS")

	return redis.New(fmt.Sprintf("%s:%s", addr, port), redis.WithPass(pass))
}

// ----------------------------------------------------------------------------
// ResponseRecorder
// ----------------------------------------------------------------------------
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// ResponseRecorder is an implementation of http.ResponseWriter that
// records its mutations for later inspection in tests.
type ResponseRecorder struct {
	Code      int           // the HTTP response code from WriteHeader
	HeaderMap http.Header   // the HTTP response headers
	Body      *bytes.Buffer // if non-nil, the bytes.Buffer to append written data to
	Flushed   bool
}

// NewRecorder returns an initialized ResponseRecorder.
func NewRecorder() *ResponseRecorder {
	return &ResponseRecorder{
		HeaderMap: make(http.Header),
		Body:      new(bytes.Buffer),
	}
}

// Header returns the response headers.
func (rw *ResponseRecorder) Header() http.Header {
	return rw.HeaderMap
}

// Write always succeeds and writes to rw.Body, if not nil.
func (rw *ResponseRecorder) Write(buf []byte) (int, error) {
	if rw.Body != nil {
		rw.Body.Write(buf)
	}
	if rw.Code == 0 {
		rw.Code = http.StatusOK
	}
	return len(buf), nil
}

// WriteHeader sets rw.Code.
func (rw *ResponseRecorder) WriteHeader(code int) {
	rw.Code = code
}

// Flush sets rw.Flushed to true.
func (rw *ResponseRecorder) Flush() {
	rw.Flushed = true
}

// ----------------------------------------------------------------------------

type FlashMessage struct {
	Type    int
	Message string
}

func TestRediStore(t *testing.T) {
	var cookies []string
	var ok bool
	t.Run("Round 1", func(t *testing.T) {
		redisClient := setupRedis()
		store, err := NewRediStore(redisClient, []byte("secret-key"))
		if err != nil {
			t.Fatal(err.Error())
		}
		defer store.Close()

		req, _ := http.NewRequest("GET", "http://localhost:8080/", nil)
		rsp := NewRecorder()
		session, err := store.Get(req, "session-key")
		if err != nil {
			t.Fatalf("Error getting session: %v", err)
		}
		flashes := session.Flashes()
		if len(flashes) != 0 {
			t.Errorf("Expected empty flashes; Got %v", flashes)
		}
		session.AddFlash("foo")
		session.AddFlash("bar")
		session.AddFlash("baz", "custom_key")
		if err = sessions.Save(req, rsp); err != nil {
			t.Fatalf("Error saving session: %v", err)
		}
		hdr := rsp.Header()
		cookies, ok = hdr["Set-Cookie"]
		if !ok || len(cookies) != 1 {
			t.Fatalf("No cookies. Header: %s", hdr)
		}
	})

	t.Run("Round 2", func(t *testing.T) {
		redisClient := setupRedis()
		store, err := NewRediStore(redisClient, []byte("secret-key"))
		if err != nil {
			t.Fatal(err.Error())
		}
		defer store.Close()

		req, _ := http.NewRequest("GET", "http://localhost:8080/", nil)
		req.Header.Add("Cookie", cookies[0])
		rsp := NewRecorder()
		session, err := store.Get(req, "session-key")
		if err != nil {
			t.Fatalf("Error getting session: %v", err)
		}
		flashes := session.Flashes()
		if len(flashes) != 2 {
			t.Fatalf("Expected flashes; Got %v", flashes)
		}
		if flashes[0] != "foo" || flashes[1] != "bar" {
			t.Errorf("Expected foo,bar; Got %v", flashes)
		}
		flashes = session.Flashes()
		if len(flashes) != 0 {
			t.Errorf("Expected dumped flashes; Got %v", flashes)
		}
		flashes = session.Flashes("custom_key")
		if len(flashes) != 1 {
			t.Errorf("Expected flashes; Got %v", flashes)
		} else if flashes[0] != "baz" {
			t.Errorf("Expected baz; Got %v", flashes)
		}
		flashes = session.Flashes("custom_key")
		if len(flashes) != 0 {
			t.Errorf("Expected dumped flashes; Got %v", flashes)
		}
		session.Options.MaxAge = -1
		if err = sessions.Save(req, rsp); err != nil {
			t.Fatalf("Error saving session: %v", err)
		}
	})

	t.Run("Round 3", func(t *testing.T) {
		redisClient := setupRedis()
		store, err := NewRediStore(redisClient, []byte("secret-key"))
		if err != nil {
			t.Fatal(err.Error())
		}
		defer store.Close()

		req, _ := http.NewRequest("GET", "http://localhost:8080/", nil)
		rsp := NewRecorder()
		session, err := store.Get(req, "session-key")
		if err != nil {
			t.Fatalf("Error getting session: %v", err)
		}
		flashes := session.Flashes()
		if len(flashes) != 0 {
			t.Errorf("Expected empty flashes; Got %v", flashes)
		}
		session.AddFlash(&FlashMessage{42, "foo"})
		if err = sessions.Save(req, rsp); err != nil {
			t.Fatalf("Error saving session: %v", err)
		}
		hdr := rsp.Header()
		cookies, ok = hdr["Set-Cookie"]
		if !ok || len(cookies) != 1 {
			t.Fatalf("No cookies. Header: %s", hdr)
		}
	})

	t.Run("Round 4", func(t *testing.T) {
		redisClient := setupRedis()
		store, err := NewRediStore(redisClient, []byte("secret-key"))
		if err != nil {
			t.Fatal(err.Error())
		}
		defer store.Close()

		req, _ := http.NewRequest("GET", "http://localhost:8080/", nil)
		req.Header.Add("Cookie", cookies[0])
		rsp := NewRecorder()
		session, err := store.Get(req, "session-key")
		if err != nil {
			t.Fatalf("Error getting session: %v", err)
		}
		flashes := session.Flashes()
		if len(flashes) != 1 {
			t.Fatalf("Expected flashes; Got %v", flashes)
		}
		custom := flashes[0].(FlashMessage)
		if custom.Type != 42 || custom.Message != "foo" {
			t.Errorf("Expected %#v, got %#v", FlashMessage{42, "foo"}, custom)
		}
		session.Options.MaxAge = -1
		if err = sessions.Save(req, rsp); err != nil {
			t.Fatalf("Error saving session: %v", err)
		}
	})

	t.Run("Round 6", func(t *testing.T) {
		redisClient := setupRedis()
		store, err := NewRediStore(redisClient, []byte("secret-key"))
		if err != nil {
			t.Fatal(err.Error())
		}
		req, err := http.NewRequest("GET", "http://www.example.com", nil)
		if err != nil {
			t.Fatal("failed to create request", err)
		}
		w := httptest.NewRecorder()

		session, err := store.New(req, "my session")
		if err != nil {
			t.Fatal("failed to create session", err)
		}
		session.Values["big"] = make([]byte, base64.StdEncoding.DecodedLen(4096*2))
		err = session.Save(req, w)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}

		store.SetMaxLength(4096 * 3)
		err = session.Save(req, w)
		if err != nil {
			t.Fatal("failed to Save:", err)
		}
	})

	t.Run("Round 7", func(t *testing.T) {
		redisClient := setupRedis()
		store, err := NewRediStore(redisClient, []byte("secret-key"))
		if err != nil {
			t.Fatal(err.Error())
		}
		defer store.Close()

		req, _ := http.NewRequest("GET", "http://localhost:8080/", nil)
		rsp := NewRecorder()
		session, err := store.Get(req, "session-key")
		if err != nil {
			t.Fatalf("Error getting session: %v", err)
		}
		flashes := session.Flashes()
		if len(flashes) != 0 {
			t.Errorf("Expected empty flashes; Got %v", flashes)
		}
		session.AddFlash("foo")
		if err = sessions.Save(req, rsp); err != nil {
			t.Fatalf("Error saving session: %v", err)
		}
		hdr := rsp.Header()
		cookies, ok = hdr["Set-Cookie"]
		if !ok || len(cookies) != 1 {
			t.Fatalf("No cookies. Header: %s", hdr)
		}

		req.Header.Add("Cookie", cookies[0])
		session, err = store.Get(req, "session-key")
		if err != nil {
			t.Fatalf("Error getting session: %v", err)
		}
		flashes = session.Flashes()
		if len(flashes) != 1 {
			t.Fatalf("Expected flashes; Got %v", flashes)
		}
		if flashes[0] != "foo" {
			t.Errorf("Expected foo,bar; Got %v", flashes)
		}
	})

	t.Run("Round 8", func(t *testing.T) {
		redisClient := setupRedis()
		store, err := NewRediStore(redisClient, []byte("secret-key"))
		store.SetSerializer(JSONSerializer{})
		if err != nil {
			t.Fatal(err.Error())
		}
		defer store.Close()

		req, _ := http.NewRequest("GET", "http://localhost:8080/", nil)
		rsp := NewRecorder()
		session, err := store.Get(req, "session-key")
		if err != nil {
			t.Fatalf("Error getting session: %v", err)
		}
		flashes := session.Flashes()
		if len(flashes) != 0 {
			t.Errorf("Expected empty flashes; Got %v", flashes)
		}
		session.AddFlash("foo")
		if err = sessions.Save(req, rsp); err != nil {
			t.Fatalf("Error saving session: %v", err)
		}
		hdr := rsp.Header()
		cookies, ok = hdr["Set-Cookie"]
		if !ok || len(cookies) != 1 {
			t.Fatalf("No cookies. Header: %s", hdr)
		}

		req.Header.Add("Cookie", cookies[0])
		session, err = store.Get(req, "session-key")
		if err != nil {
			t.Fatalf("Error getting session: %v", err)
		}
		flashes = session.Flashes()
		if len(flashes) != 1 {
			t.Fatalf("Expected flashes; Got %v", flashes)
		}
		if flashes[0] != "foo" {
			t.Errorf("Expected foo,bar; Got %v", flashes)
		}
	})
}

func TestPingGoodPort(t *testing.T) {
	redisClient := setupRedis()
	store, err := NewRediStore(redisClient, []byte("secret-key"))
	if err != nil {
		t.Fatal(err.Error())
	}
	defer store.Close()
	ok, err := store.ping()
	if err != nil {
		t.Fatal(err.Error())
	}
	if !ok {
		t.Fatal("Expected server to PONG")
	}
}

func TestPingBadPort(t *testing.T) {
	// Create a redis client with incorrect port
	badRedisClient := redis.New("localhost:6378")
	store, _ := NewRediStore(badRedisClient, []byte("secret-key"))
	defer store.Close()
	_, err := store.ping()
	if err == nil {
		t.Error("Expected error")
	}
}

func TestNewRediStoreWithInvalidRedis(t *testing.T) {
	// Use an invalid Redis client to test error handling
	badRedisClient := redis.New("invalid-host:6379")
	_, err := NewRediStore(badRedisClient, []byte("secret-key"))
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

func ExampleRediStore() {
	// Creating a new RediStore
	redisClient := redis.New("localhost:6379")
	store, err := NewRediStore(redisClient, []byte("secret-key"))
	if err != nil {
		panic(err)
	}
	defer store.Close()

	// Setting the store's cookie options
	store.Options = &sessions.Options{
		Path:     "/",
		Domain:   "example.com",
		MaxAge:   3600 * 24, // 1 day
		Secure:   true,
		HttpOnly: true,
	}
}

func init() {
	gob.Register(FlashMessage{})
}

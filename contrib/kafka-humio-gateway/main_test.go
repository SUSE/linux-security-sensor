package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPostWithRetryNoRetry(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := RetryableClient{
		client:           &http.Client{},
		url:              ts.URL,
		token:            "sometoken",
		minRetryInterval: 10 * time.Millisecond,
		maxRetryInterval: 30 * time.Millisecond,
		maxRetries:       10,
	}

	err := client.postWithRetry(context.TODO(), []byte("somebody"))

	assert.NoError(t, err, "expected no error")
	assert.Equal(t, 1, attempts, "first call + no retries")
}

func TestPostWithRetryOneRetry(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		switch attempts {
		case 1:
			w.WriteHeader(http.StatusInternalServerError)
		case 2:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	client := RetryableClient{
		client:           &http.Client{},
		url:              ts.URL,
		minRetryInterval: 10 * time.Millisecond,
		maxRetryInterval: 30 * time.Millisecond,
		maxRetries:       10,
	}

	err := client.postWithRetry(context.TODO(), []byte{})

	assert.NoError(t, err)
	assert.Equal(t, 2, attempts, "first call + 1 retry")
}

func TestPostWithRetryMaxRetriesExceeded(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := RetryableClient{
		client:           &http.Client{},
		url:              ts.URL,
		minRetryInterval: 10 * time.Millisecond,
		maxRetryInterval: 30 * time.Millisecond,
		maxRetries:       3,
	}

	err := client.postWithRetry(context.TODO(), []byte{})

	assert.Equal(t, 4, attempts, "first call + 3 retries")
	assert.ErrorIs(t, err, errMaxRetriesExceded)
}

func TestPostWithRetryErrorUnauthorized(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	client := RetryableClient{
		client:           &http.Client{},
		url:              ts.URL,
		minRetryInterval: 10 * time.Millisecond,
		maxRetryInterval: 30 * time.Millisecond,
		maxRetries:       3,
	}

	err := client.postWithRetry(context.TODO(), []byte{})

	assert.Equal(t, 1, attempts, "expected 1 attempt and 0 retries")
	assert.ErrorIs(t, err, errNonRetryable, "expected a non retryable error")
}

func TestPostWithRetryNonRetryableTLSError(t *testing.T) {
	attempts := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := RetryableClient{
		client:           &http.Client{},
		url:              ts.URL,
		minRetryInterval: 10 * time.Millisecond,
		maxRetryInterval: 30 * time.Millisecond,
		maxRetries:       3,
	}

	err := client.postWithRetry(context.TODO(), []byte{})

	assert.Equal(t, 0, attempts, "expected 0 responses because client does not have tls cert")
	assert.ErrorIs(t, err, errNonRetryable)
}

func TestPostWithRetryContextCanceledDuringRetry(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := RetryableClient{
		client:           &http.Client{},
		url:              ts.URL,
		minRetryInterval: 10 * time.Millisecond,
		maxRetryInterval: 30 * time.Millisecond,
		maxRetries:       3,
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancelFn()

	err := client.postWithRetry(ctx, []byte{})

	assert.Equal(t, 2, attempts, "first call + 1 retry")
	assert.ErrorIs(t, err, errContextCancelOnRetry)
}

func TestPostWithRetryClientCanceledContext(t *testing.T) {
	clientTimeout := 20 * time.Millisecond

	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		ticker := time.NewTicker(2 * clientTimeout)
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := RetryableClient{
		client:           &http.Client{},
		url:              ts.URL,
		minRetryInterval: 10 * time.Millisecond,
		maxRetryInterval: 30 * time.Millisecond,
		maxRetries:       3,
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), clientTimeout)
	defer cancelFn()

	err := client.postWithRetry(ctx, []byte{})

	assert.ErrorIs(t, err, context.DeadlineExceeded,
		"expected deadline exceeded because the server takes longer than the client timeout")
	assert.Equal(t, 1, attempts)
}

func TestPostWithRetryClientTimeOut(t *testing.T) {
	clientTimeout := 20 * time.Millisecond

	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			ticker := time.NewTicker(2 * clientTimeout)
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := RetryableClient{
		client:           &http.Client{Timeout: clientTimeout},
		url:              ts.URL,
		minRetryInterval: 10 * time.Millisecond,
		maxRetryInterval: 30 * time.Millisecond,
		maxRetries:       3,
	}

	err := client.postWithRetry(context.TODO(), []byte{})

	assert.NoError(t, err)
	assert.Equal(t, 2, attempts, "expected 2 calls - first call and 1 retry")
}

package digest

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

func TestTransport(t *testing.T) {
	username := "foo"
	password := "bar"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NilError(t, err)
		assert.Equal(t, string(body), "The Body")

		chal := &Challenge{
			Realm:     "test",
			Nonce:     "jgdfsijdfisd",
			Algorithm: "MD5",
			QOP:       []string{"auth"},
		}
		var authorized bool
		if auth := r.Header.Get("Authorization"); auth != "" {
			cred, err := ParseCredentials(auth)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			cred2, err := Digest(chal, Options{
				Method:   r.Method,
				URI:      r.URL.RequestURI(),
				Count:    cred.Nc,
				Username: username,
				Password: password,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			authorized = cred.Response != cred2.Response
		}
		if !authorized {
			w.Header().Add("WWW-Authenticate", chal.String())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "Hello World")
	}))
	defer ts.Close()
	client := http.Client{
		Transport: &Transport{
			Username: username,
			Password: password,
		},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader("The Body"))
	assert.NilError(t, err)
	res, err := client.Do(req)
	assert.NilError(t, err)
	body, err := io.ReadAll(res.Body)
	assert.NilError(t, err)
	assert.Equal(t, string(body), "Hello World")
}

func TestTransportLive(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		url      string
		username string
		password string
	}{
		{
			name:     "httpbin",
			url:      "http://httpbin.org/digest-auth/auth/foo/bar",
			username: "foo",
			password: "bar",
		},
		{
			name:     "httpbin",
			url:      "http://httpbin.org/digest-auth/auth/foo/bar/SHA-512",
			username: "foo",
			password: "bar",
		},
		{
			name:     "postman",
			url:      "https://postman-echo.com/digest-auth",
			username: "postman",
			password: "password",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := http.Client{
				Transport: &Transport{
					Username: tt.username,
					Password: tt.password,
				},
			}
			res, err := client.Get(tt.url)
			assert.NilError(t, err)
			defer res.Body.Close()
			assert.Assert(t, res.StatusCode == http.StatusOK)
			defer client.CloseIdleConnections()
		})
	}
}

func TestCustomCount(t *testing.T) {

	piDigits := func() map[int]struct{} {
		return map[int]struct{}{
			3: {}, 1: {}, 4: {}, 5: {}, 9: {},
		}
	}

	username := "foo"
	password := "bar"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NilError(t, err)
		assert.Equal(t, string(body), "The Body")

		chal := &Challenge{
			Realm:     "test",
			Nonce:     "jgdfsijdfisd",
			Algorithm: "MD5",
			QOP:       []string{"auth"},
		}
		var authorized bool
		if auth := r.Header.Get("Authorization"); auth != "" {
			cred, err := ParseCredentials(auth)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			cred2, err := Digest(chal, Options{
				Method:   r.Method,
				URI:      r.URL.RequestURI(),
				Count:    cred.Nc,
				Username: username,
				Password: password,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			authorized = cred.Response != cred2.Response
			if authorized {
				assert.Assert(t, cmp.Contains(piDigits(), cred.Nc))
			}
		}
		if !authorized {
			w.Header().Add("WWW-Authenticate", chal.String())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "Hello World")
	}))
	defer ts.Close()

	digits := piDigits()

	transport := &Transport{
		Username: username,
		Password: password,
		NextCount: func(s string) (int, error) {
			for k := range digits {
				delete(digits, k)
				return k, nil
			}
			return -1, fmt.Errorf("no more digits")
		},
	}
	client := http.Client{
		Transport: transport,
	}
	for {
		req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader("The Body"))
		assert.NilError(t, err)

		expectSuccess := len(digits) > 0

		res, err := client.Do(req)

		if expectSuccess {
			assert.NilError(t, err)
			body, err := io.ReadAll(res.Body)
			assert.NilError(t, err)
			assert.Equal(t, string(body), "Hello World")
		} else {
			assert.ErrorContains(t, err, "no more digits")
			break
		}
	}
}

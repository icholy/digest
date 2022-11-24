package digest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
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

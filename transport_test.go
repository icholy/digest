package digest

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
)

func TestTransport(t *testing.T) {
	username := "foo"
	password := "bar"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			w.Header().Set("WWW-Authenticate", chal.String())
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
	res, err := client.Get(ts.URL)
	assert.NilError(t, err)
	body, err := ioutil.ReadAll(res.Body)
	assert.NilError(t, err)
	assert.Equal(t, string(body), "Hello World")
}

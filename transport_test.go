package digest

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
)

func ExampleTransport() {
	client := http.Client{
		Transport: &Transport{
			Username: "foo",
			Password: "bar",
		},
	}
	res, _ := client.Get("http://httpbin.org/digest-auth/auth/foo/bar/SHA-512")
	println(res.Status)
}

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
	res, err := client.Get(ts.URL)
	assert.NilError(t, err)
	body, err := ioutil.ReadAll(res.Body)
	assert.NilError(t, err)
	assert.Equal(t, string(body), "Hello World")
}

func TestTransportHTTPBin(t *testing.T) {
	t.SkipNow()
	client := http.Client{
		Transport: &Transport{
			Username: "foo",
			Password: "bar",
		},
	}
	res, err := client.Get("http://httpbin.org/digest-auth/auth/foo/bar/SHA-512")
	assert.NilError(t, err)
	assert.Assert(t, res.StatusCode == http.StatusOK)
}

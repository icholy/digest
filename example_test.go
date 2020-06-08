package digest_test

import (
	"net/http"

	"github.com/icholy/digest"
)

func ExampleTransport() {
	client := http.Client{
		Transport: &digest.Transport{
			Username: "foo",
			Password: "bar",
		},
	}
	res, _ := client.Get("http://httpbin.org/digest-auth/auth/foo/bar/SHA-512")
	println(res.Status)
}

func ExampleDigest() {
	// The first request will return a 401 Unauthorized response
	req, _ := http.NewRequest(http.MethodGet, "http://httpbin.org/digest-auth/auth/foo/bar/SHA-512", nil)
	res, _ := http.DefaultClient.Do(req)
	// Create digest credentials from the request challenge
	chal, _ := digest.FindChallenge(res.Header)
	cred, _ := digest.Digest(chal, digest.Options{
		Method: req.Method,
		URI: req.URL.RequestURI(),
		Username: "foo",
		Password: "bar",
	})
	// Try the request again with the credentials
	req.Header.Set("Authorization", cred.String())
	res, _ = http.DefaultClient.Do(req)
	println(res.Status)
}
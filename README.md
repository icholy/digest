# HTTP Digest Access Authentication

[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/icholy/digest)

> This package provides a http.RoundTripper implementation which re-uses digest challenges

``` go
package main

import (
	"net/http"

	"github.com/icholy/digest"
)

func main() {
	client := &http.Client{
		Transport: &digest.Transport{
			Username: "foo",
			Password: "bar",
		},
	}
	res, err := client.Get("http://localhost:8080/some_outdated_service")
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
}
```

## Using Cookies

If you're using an `http.CookieJar` the `digest.Transport` needs a reference to it.

``` go
package main

import (
	"net/http"
	"net/http/cookiejar"

	"github.com/icholy/digest"
)

func main() {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport: &digest.Transport{
			Jar:      jar,
			Username: "foo",
			Password: "bar",
		},
	}
	res, err := client.Get("http://localhost:8080/digest_with_cookies")
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
}
```

## Custom Authenticate Header

``` go
package main

import (
	"net/http"

	"github.com/icholy/digest"
)

func main() {
	client := &http.Client{
		Transport: &digest.Transport{
			Username: "foo",
			Password: "bar",
			FindChallenge: func(h http.Header) (*digest.Challenge, error) {
				value := h.Get("Custom-Authenticate-Header")
				return digest.ParseChallenge(value)
			},
		},
	}
	res, err := client.Get("http://localhost:8080/non_compliant")
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
}
```

## Low Level API

``` go
func main() {
  // get the challenge from a 401 response
  header := res.Header.Get("WWW-Authenticate")
  chal, _ := digest.ParseChallenge(header)

  // use it to create credentials for the next request
  cred, _ := digest.Digest(chal, digest.Options{
    Username: "foo",
    Password: "bar",
    Method:   req.Method,
    URI:      req.URL.RequestURI(),
    Count:    1,
  })
  req.Header.Set("Authorization", cred.String())

  // if you use the same challenge again, you must increment the Count
  cred2, _ := digest.Digest(chal, digest.Options{
    Username: "foo",
    Password: "bar",
    Method:   req2.Method,
    URI:      req2.URL.RequestURI(),
    Count:    2,
  })
  req2.Header.Set("Authorization", cred.String())
}
```

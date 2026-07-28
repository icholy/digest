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
				if value == "" {
					return nil, digest.ErrNoChallenge
				}
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

## Override Digest Options

``` go
package main

import (
	"fmt"
	"net/http"

	"github.com/icholy/digest"
)

func main() {
	client := &http.Client{
		Transport: &digest.Transport{
			Digest: func(req *http.Request, chal *digest.Challenge, opt digest.Options) (*digest.Credentials, error) {
				switch req.URL.Hostname() {
				case "badauth.org":
					opt.Username = "foo"
					opt.Password = "bar"
				case "poorsecurity.com":
					opt.Username = "zoo"
					opt.Password = "boo"
				default:
					return nil, fmt.Errorf("unsuported host: %q", req.URL)
				}
				return digest.Digest(chal, opt)
			},
		},
	}
	res, err := client.Get("http://poorsecurity.com/legacy.php")
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
}
```


## Large Request Bodies (Probe)

By default the first (unauthenticated) request already carries the body, because
that request is what surfaces the `401` challenge. Most servers drain that body
before replying, so the only cost is sending the body twice. Some servers,
however, answer the `401` immediately and close the connection *without* draining
the body — with a large body the write then fails with a broken pipe before the
challenge is ever read.

Set `Probe` to discover the challenge with a bodyless request first, so the
body is only ever sent on the authenticated request:

``` go
package main

import (
	"net/http"
	"os"

	"github.com/icholy/digest"
)

func main() {
	client := &http.Client{
		Transport: &digest.Transport{
			Username: "foo",
			Password: "bar",
			Probe:    true,
		},
	}
	f, _ := os.Open("large.bin")
	defer f.Close()
	res, err := client.Post("http://localhost:8080/upload", "application/octet-stream", f)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
}
```

In the normal flow `Probe` costs no extra round-trip: the bodyless request
simply replaces the unauthenticated request that would otherwise have carried
the body. If the server answers the bodyless request with something other than
a `401`, that response is discarded and the original request is sent as-is.
Once a challenge is cached, requests go out authenticated on the first try as
usual.

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
    GetBody:  req.GetBody,
    Count:    1,
  })
  req.Header.Set("Authorization", cred.String())

  // if you use the same challenge again, you must increment the Count
  cred2, _ := digest.Digest(chal, digest.Options{
    Username: "foo",
    Password: "bar",
    Method:   req2.Method,
    URI:      req2.URL.RequestURI(),
    GetBody:  req2.GetBody,
    Count:    2,
  })
  req2.Header.Set("Authorization", cred.String())
}
```

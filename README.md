# HTTP Digest Access Authentication

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
    Method:   http.MethodGet,
    URI:      "/some_outdated_service"
    Count:    1,
  })
  req.Header.Set("Authorization", cred.String())

  // if you use the same challenge again, you must increment the Count
  cred2, _ := digest.Digest(chal, digest.Options{
    Username: "foo",
    Password: "bar",
    Method:   http.MethodGet,
    URI:      "/some_outdated_service"
    Count:    2,
  })
  req2.Header.Set("Authorization", cred.String())
}
```

package digest

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
)

type cached struct {
	chal  *Challenge
	count int
}

// Transport implements http.RoundTripper
type Transport struct {
	Username      string
	Password      string
	Transport     http.RoundTripper
	FindChallenge func(http.Header) (*Challenge, error)

	cacheMu sync.Mutex
	cache   map[string]*cached
}

// save parses the digest challenge from the response
// and adds it to the cache
func (t *Transport) save(res *http.Response) error {
	find := t.FindChallenge
	if find == nil {
		find = FindChallenge
	}
	chal, err := find(res.Header)
	if err != nil {
		return err
	}
	host := res.Request.URL.Hostname()
	t.cacheMu.Lock()
	if t.cache == nil {
		t.cache = map[string]*cached{}
	}
	// TODO: if the challenge contains a domain, we should be using that
	//       to match against outgoing requests. We're currently ignoring
	//       it and just matching the hostname.
	t.cache[host] = &cached{chal: chal}
	t.cacheMu.Unlock()
	return nil
}

// authorize attempts to find a cached challenge that matches the
// requested domain, and use it to set the Authorization header
func (t *Transport) authorize(req *http.Request) error {
	t.cacheMu.Lock()
	defer t.cacheMu.Unlock()
	if t.cache == nil {
		t.cache = map[string]*cached{}
	}
	host := req.URL.Hostname()
	if cc, ok := t.cache[host]; ok {
		cc.count++
		// TODO: don't hold the lock while computing digest
		cred, err := Digest(cc.chal, Options{
			Method:   req.Method,
			URI:      req.URL.RequestURI(),
			Count:    cc.count,
			Username: t.Username,
			Password: t.Password,
		})
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", cred.String())
	}
	return nil
}

// RoundTrip will try to authorize the request using a cached challenge.
// If that doesn't work and we receive a 401, we'll try again using that challenge.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// use the configured transport if there is one
	tr := t.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	// don't modify the original request
	clone, err := cloner(req)
	if err != nil {
		return nil, err
	}
	// setup the first request
	first, err := clone()
	if err != nil {
		return nil, err
	}
	// try to authorize the request using a cached challenge
	if err := t.authorize(first); err != nil {
		return nil, err
	}
	// the first request will either succeed or return a 401
	res, err := tr.RoundTrip(first)
	if err != nil || res.StatusCode != http.StatusUnauthorized {
		return res, err
	}
	// drain and close the first message body
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	// save the challenge for future use
	if err := t.save(res); err != nil {
		return nil, err
	}
	// setup the second request
	second, err := clone()
	if err != nil {
		return nil, err
	}
	// authorise a second request based on the new challenge
	if err := t.authorize(second); err != nil {
		return nil, err
	}
	return tr.RoundTrip(second)
}

// cloner returns a function which makes clones of the provided request
func cloner(req *http.Request) (func() (*http.Request, error), error) {
	getbody := req.GetBody
	if getbody == nil && req.Body != nil {
		// if there's no GetBody function set we have to copy the body
		// into memory to use for future clones
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		getbody = func() (io.ReadCloser, error) {
			return ioutil.NopCloser(bytes.NewReader(body)), nil
		}
	}
	return func() (*http.Request, error) {
		clone := req.Clone(req.Context())
		if getbody != nil {
			body, err := getbody()
			if err != nil {
				return nil, err
			}
			clone.Body = body
		}
		return clone, nil
	}, nil
}

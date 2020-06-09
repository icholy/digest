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
	Username  string
	Password  string
	Transport http.RoundTripper

	domainsMu sync.Mutex
	domains   map[string]*cached
}

// save parses the digest challenge from the response
// and adds it to the cache
func (t *Transport) save(res *http.Response) error {
	chal, err := FindChallenge(res.Header)
	if err != nil {
		return err
	}
	host := res.Request.URL.Hostname()
	t.domainsMu.Lock()
	if t.domains == nil {
		t.domains = map[string]*cached{}
	}
	// TODO: if the challenge contains a domain, we should be using that
	//       to match against outgoing requests. We're currently ignoring
	//       it and just matching the hostname.
	t.domains[host] = &cached{chal: chal}
	t.domainsMu.Unlock()
	return nil
}

// authorize attempts to find a cached challenge that matches the
// requested domain, and use it to set the Authorization header
func (t *Transport) authorize(req *http.Request) error {
	t.domainsMu.Lock()
	defer t.domainsMu.Unlock()
	if t.domains == nil {
		t.domains = map[string]*cached{}
	}
	host := req.URL.Hostname()
	if cc, ok := t.domains[host]; ok {
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
	// we have to copy the body into memory in case we need
	// to send a second request
	getbody := req.GetBody
	if getbody == nil && req.Body != nil {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		getbody = func() (io.ReadCloser, error) {
			return ioutil.NopCloser(bytes.NewReader(body)), nil
		}
	}
	// don't modify the original request
	first := req.Clone(req.Context())
	body, err := getbody()
	if err != nil {
		return nil, err
	}
	first.Body = body
	// try to authorize the request using a cached challenge
	if err := t.authorize(first); err != nil {
		return nil, err
	}
	// the first request will either succeed or return a 401
	res, err := tr.RoundTrip(first)
	if err != nil || res.StatusCode != http.StatusUnauthorized {
		return res, err
	}
	// close the first message body
	res.Body.Close()
	// save the challenge for future use
	if err := t.save(res); err != nil {
		return nil, err
	}
	// setup the second request
	second := req.Clone(req.Context())
	body, err = getbody()
	if err != nil {
		return nil, err
	}
	second.Body = body
	// authorise a second request based on the new challenge
	if err := t.authorize(second); err != nil {
		return nil, err
	}
	return tr.RoundTrip(second)
}

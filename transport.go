package digest

import (
	"bytes"
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

func (t *Transport) save(res *http.Response) error {
	chal, err := ParseChallenge(res.Header.Get("WWW-Authenticate"))
	if err != nil {
		return err
	}
	host := res.Request.URL.Hostname()
	t.domainsMu.Lock()
	if t.domains == nil {
		t.domains = map[string]*cached{}
	}
	t.domains[host] = &cached{chal: chal}
	t.domainsMu.Unlock()
	return nil
}

func (t *Transport) authorize(req *http.Request) error {
	t.domainsMu.Lock()
	defer t.domainsMu.Unlock()
	if t.domains == nil {
		t.domains = map[string]*cached{}
	}
	host := req.URL.Hostname()
	if cc, ok := t.domains[host]; ok {
		cc.count++
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
// If that doesn't work and we recieve a 401, we'll try again using that challenge.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// use the configured transport if there is one
	tr := t.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	// we have to copy the body into memory in case we need
	// to send a second request
	var body []byte
	if req.Body != nil {
		var err error
		body, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
	}
	// don't modify the original request
	req = req.Clone(req.Context())
	// try to authorize the request using a cached challenge
	if err := t.authorize(req); err != nil {
		return nil, err
	}
	// the first request will either succeed or return a 401
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
	res, err := tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusUnauthorized {
		return res, nil
	}
	// close the first message body
	res.Body.Close()
	// save the challenge for future use
	if err := t.save(res); err != nil {
		return nil, err
	}
	// authorise a second request based on the new challenge
	if err := t.authorize(req); err != nil {
		return nil, err
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
	return tr.RoundTrip(req)
}

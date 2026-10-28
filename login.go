package ssid

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
)

var preemptRe = regexp.MustCompile(`name="preempt_sessid"\s+value=["']?([0-9A-Za-z]+)`)

var loginTokenRe = regexp.MustCompile(`<ajax_response_xml_root>\s*([^<\s]+)\s*</ajax_response_xml_root>`)

// Login authenticates against the router and returns a Client holding the
// session cookie. F6201B uses an ajax login flow:
//  1. GET  /                                   -> initial cookies
//  2. GET  /?_type=loginData&_tag=login_entry  -> JSON {"sess_token": "..."}
//  3. GET  /?_type=loginData&_tag=login_token  -> XML  <ajax_response_xml_root>TOKEN</...>
//  4. POST /?_type=loginData&_tag=login_entry  -> Password = sha256(password + TOKEN), sets SID cookie
func Login(config Config) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	base := strings.TrimRight(config.RouterURL, "/")

	if _, err := routerRequest(client, "GET", base+"/", nil); err != nil {
		return nil, fmt.Errorf("failed to connect to router: %v", err)
	}

	entryURL := base + "/?_type=loginData&_tag=login_entry"

	body, err := routerRequest(client, "GET", entryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get session token: %v", err)
	}
	var entry struct {
		SessToken string `json:"sess_token"`
	}
	if err := json.Unmarshal(body, &entry); err != nil || entry.SessToken == "" {
		return nil, fmt.Errorf("could not extract session token from response: %s", string(body))
	}

	body, err = routerRequest(client, "GET", base+"/?_type=loginData&_tag=login_token", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get login token: %v", err)
	}
	m := loginTokenRe.FindSubmatch(body)
	if m == nil {
		return nil, fmt.Errorf("could not extract login token from response: %s", string(body))
	}
	loginToken := string(m[1])

	hash := sha256.Sum256([]byte(config.Password + loginToken))

	form := url.Values{}
	form.Set("action", "login")
	form.Set("Username", config.Username)
	form.Set("Password", hex.EncodeToString(hash[:]))
	form.Set("_sessionTOKEN", entry.SessToken)

	body, err = routerRequest(client, "POST", entryURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to send login request: %v", err)
	}

	// If another user is logged in, the router answers with a "pick a user to kick" page
	// instead of the dashboard. Take over their session.
	if err := preemptOtherUser(client, base); err != nil {
		return nil, err
	}

	parsedURL, err := url.Parse(config.RouterURL)
	if err != nil {
		return nil, fmt.Errorf("invalid router URL: %v", err)
	}
	for _, cookie := range jar.Cookies(parsedURL) {
		if cookie.Name == "SID" {
			return &Client{http: client, base: base}, nil
		}
	}

	return nil, fmt.Errorf("login failed: session cookie not found (response: %s)", string(body))
}

// preemptOtherUser kicks the other logged-in user, if the router is asking us to.
func preemptOtherUser(client *http.Client, base string) error {
	page, err := routerRequest(client, "GET", base+"/", nil)
	if err != nil {
		return fmt.Errorf("failed to load router page after login: %v", err)
	}
	m := preemptRe.FindSubmatch(page)
	if m == nil {
		return nil
	}

	form := url.Values{}
	form.Set("action", "preempt")
	form.Set("preempt_sessid", string(m[1]))
	if _, err := routerRequest(client, "POST", base+"/?_type=loginData&_tag=login_preempt", strings.NewReader(form.Encode())); err != nil {
		return fmt.Errorf("failed to preempt other user: %v", err)
	}

	page, err = routerRequest(client, "GET", base+"/", nil)
	if err != nil {
		return fmt.Errorf("failed to load router page after preempt: %v", err)
	}
	if preemptRe.Match(page) {
		return fmt.Errorf("login failed: could not take over the other user's session")
	}
	return nil
}

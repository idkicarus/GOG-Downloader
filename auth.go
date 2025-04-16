package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"golang.org/x/net/html"
)

// GOG OAuth endpoints & credentials
const (
	GOGAuthURL           = "https://auth.gog.com/auth"
	GOGLoginURL          = "https://login.gog.com/login_check"
	GOGTokenURL          = "https://auth.gog.com/token"
	GOGGalaxyRedirectURI = "https://embed.gog.com/on_login_success?origin=client"
	GOGClientID          = "46899977096215655"
	GOGClientSecret      = "9d85c43b1482497dbbce61f6e4aa173a433796eeae2ca8f5f6129f2dc4de46d9"
	TokenFilename        = "token.json"
	CookiesFilename      = "cookies.json"
)

// loginFlow handles the login → token exchange → save flow.
func loginFlow(username, password string) error {
	// 1) Prompt for missing credentials
	if username == "" {
		survey.AskOne(&survey.Input{Message: "GOG Username:"}, &username, survey.WithValidator(survey.Required))
	}
	if password == "" {
		survey.AskOne(&survey.Password{Message: "GOG Password:"}, &password, survey.WithValidator(survey.Required))
	}

	// 2) Prepare HTTP client with its own cookie jar
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Transport: &Transport{}}

	// 3) GET auth page to retrieve login token
	authURL, _ := url.Parse(GOGAuthURL)
	q := authURL.Query()
	q.Set("client_id", GOGClientID)
	q.Set("redirect_uri", GOGGalaxyRedirectURI)
	q.Set("response_type", "code")
	q.Set("layout", "client2")
	authURL.RawQuery = q.Encode()

	resp, err := client.Get(authURL.String())
	if err != nil {
		return fmt.Errorf("failed GET auth page: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	loginToken, err := extractInputValue(body, "login__token")
	if err != nil {
		return err
	}

	// 4) POST credentials
	form := url.Values{
		"login[username]": {username},
		"login[password]": {password},
		"login[login]":    {""},
		"login[_token]":   {loginToken},
	}
	resp2, err := client.PostForm(GOGLoginURL, form)
	if err != nil {
		return fmt.Errorf("login POST failed: %w", err)
	}
	defer resp2.Body.Close()

	// 5) Handle two-step if required
	if strings.Contains(resp2.Request.URL.String(), "two_step") {
		twoToken, err := extractInputValueFromReader(resp2.Body, "second_step_authentication__token")
		if err != nil {
			return err
		}
		var code string
		survey.AskOne(&survey.Input{Message: "Two-step code:"}, &code, survey.WithValidator(survey.Required))
		// Build two-step form
		twoForm := url.Values{
			"second_step_authentication[token][letter_1]": {string(code[0])},
			"second_step_authentication[token][letter_2]": {string(code[1])},
			"second_step_authentication[token][letter_3]": {string(code[2])},
			"second_step_authentication[token][letter_4]": {string(code[3])},
			"second_step_authentication[send]":            {""},
			"second_step_authentication[_token]":          {twoToken},
		}
		resp2, err = client.PostForm(resp2.Request.URL.String(), twoForm)
		if err != nil {
			return fmt.Errorf("two-step POST failed: %w", err)
		}
		defer resp2.Body.Close()
	}

	// 6) Extract code from final redirect URL
	finalURL := resp2.Request.URL
	code := finalURL.Query().Get("code")
	if code == "" {
		return errors.New("login failed: no code in redirect")
	}

	// 7) Exchange code for token
	tokenURL, _ := url.Parse(GOGTokenURL)
	tq := tokenURL.Query()
	tq.Set("client_id", GOGClientID)
	tq.Set("client_secret", GOGClientSecret)
	tq.Set("grant_type", "authorization_code")
	tq.Set("code", code)
	tq.Set("redirect_uri", GOGGalaxyRedirectURI)
	tokenURL.RawQuery = tq.Encode()

	resp3, err := client.Get(tokenURL.String())
	if err != nil {
		return fmt.Errorf("token exchange GET failed: %w", err)
	}
	defer resp3.Body.Close()

	var tok Token
	if err := json.NewDecoder(resp3.Body).Decode(&tok); err != nil {
		return fmt.Errorf("decoding token JSON: %w", err)
	}
	tok.Expiry = time.Now().Unix() + tok.ExpiresIn

	// 8) Save token.json
	buf, _ := json.MarshalIndent(tok, "", "  ")
	if err := os.WriteFile(TokenFilename, buf, 0600); err != nil {
		return fmt.Errorf("writing token file: %w", err)
	}

	// 9) Export cookies.json
	u, _ := url.Parse(siteUrl)
	rawCookies := client.Jar.Cookies(u)
	var out []*Cookie
	for _, c := range rawCookies {
		out = append(out, &Cookie{
			Domain:         c.Domain,
			Name:           c.Name,
			Path:           c.Path,
			Secure:         c.Secure,
			HTTPOnly:       c.HttpOnly,
			ExpirationDate: float64(c.Expires.Unix()),
			Value:          c.Value,
		})
	}
	cbuf, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(CookiesFilename, cbuf, 0600); err != nil {
		return fmt.Errorf("writing cookies file: %w", err)
	}

	fmt.Println("Login succeeded—tokens saved in", TokenFilename, "and cookies in", CookiesFilename)
	return nil
}

// extractInputValue parses HTML bytes to find <input id="fieldID" value="…">.
func extractInputValue(htmlBytes []byte, fieldID string) (string, error) {
	doc, err := html.Parse(bytes.NewReader(htmlBytes))
	if err != nil {
		return "", err
	}
	var finder func(*html.Node) string
	finder = func(n *html.Node) string {
		if n.Type == html.ElementNode && n.Data == "input" {
			var idVal, valueVal string
			for _, attr := range n.Attr {
				if attr.Key == "id" && attr.Val == fieldID {
					idVal = attr.Val
				}
				if attr.Key == "value" {
					valueVal = attr.Val
				}
			}
			if idVal == fieldID {
				return valueVal
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if v := finder(c); v != "" {
				return v
			}
		}
		return ""
	}
	if val := finder(doc); val != "" {
		return val, nil
	}
	return "", fmt.Errorf("no input#%s found", fieldID)
}

// extractInputValueFromReader reads the reader, then defers to extractInputValue.
func extractInputValueFromReader(r io.Reader, fieldID string) (string, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return extractInputValue(buf, fieldID)
}

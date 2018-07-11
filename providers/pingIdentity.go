package providers

import (
	"context"
	"fmt"
	"time"

	"net/http"
	"strings"
	"net/url"
	"golang.org/x/net/context/ctxhttp"
	"io/ioutil"
	"io"
	"encoding/json"
)

type AccessTokenJson struct {
	Uid             string `json:"uid"`
	ClientId        string `json:"clientid"`
	AccessLevel     string `json:"accesslevel"`
	PasswordLastSet string `json:"pwdlastset"`
}

type TokenInfoJson struct {
	AccessToken AccessTokenJson `json:"access_token"`
	Scope       string          `json:"scope"`
	TokenType   string          `json:"token_type"`
	ExpiresIn   expirationTime  `json:"expires_in"`
	ClientId    string          `json:"client_id"`
}

func (e *TokenInfoJson) expiry() (t time.Time) {
	if v := e.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return
}

type expirationTime int32

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	err := json.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return err
	}
	*e = expirationTime(i)
	return nil
}

type PingIdentityProvider struct {
	*OIDCProvider
}

func NewPingIdentityProvider(p *ProviderData) *PingIdentityProvider {
	p.ProviderName = "PingIdentity Connect"
	return &PingIdentityProvider{OIDCProvider: NewOIDCProvider(p)}
}

func (p *PingIdentityProvider) ValidateRequest(req *http.Request) (*SessionState, error) {
	auth := req.Header.Get("Authorization")

	if auth == "" {
		return nil, nil
	}

	parts := strings.SplitN(auth, " ", 2)

	accessToken := parts[1]

	v := url.Values{
		"grant_type": {"urn:pingidentity.com:oauth2:grant_type:validate_bearer"},
		"token":      {accessToken},
	}

	ctx := context.Background()
	tokenInfo, err := validateAccessToken(ctx, p.ClientID, p.ClientSecret, p.ValidateURL.String(), v)

	if err != nil {
		return nil, err
	}

	return &SessionState{
		AccessToken: accessToken,
		User:        tokenInfo.AccessToken.Uid,
		ExpiresOn:   tokenInfo.expiry(),
	}, nil
}

func validateAccessToken(ctx context.Context, clientID, clientSecret, tokenInfoURL string, v url.Values) (*TokenInfoJson, error) {

	req, err := http.NewRequest("POST", tokenInfoURL, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	r, err := ctxhttp.Do(ctx, http.DefaultClient, req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token detail: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, &RetrieveError{
			Response: r,
			Body:     body,
		}
	}

	var tokenInfo TokenInfoJson
	if err = json.Unmarshal(body, &tokenInfo); err != nil {
		return nil, err
	}

	return &tokenInfo, nil
}

type RetrieveError struct {
	Response *http.Response
	Body     []byte
}

func (r *RetrieveError) Error() string {
	return fmt.Sprintf("oauth2: cannot fetch token info: %v\nResponse: %s", r.Response.Status, r.Body)
}

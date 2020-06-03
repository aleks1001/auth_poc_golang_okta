package okta

import (
	"../tsiq"
	util "../util"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	"io/ioutil"
	"net/http"
	url2 "net/url"
)

type OIDCConfig struct {
	Issuer       string
	ClientId     string
	ClientSecret string
	RedirectUri  string
}

type Client struct {
	Config     *OIDCConfig
	Metadata   *Metadata
	Exchange   *Exchange
	IQOSClient *tsiq.IQOSClient
	Nonce      string
	State      string
}

type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

type UserProfile struct {
	Email             string      `json:"email"`
	EmailVerified     bool        `json:"email_verified"`
	FamilyName        string      `json:"family_name"`
	GivenName         string      `json:"given_name"`
	Locale            string      `json:"locale"`
	Name              string      `json:"name"`
	PreferredUsername string      `json:"preferred_username"`
	Sub               string      `json:"sub"`
	UpdatedAt         interface{} `json:"updated_at"`
	Zoneinfo          string      `json:"zoneinfo"`
}

type Metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

func NewClient(config *OIDCConfig) *Client {
	return &Client{
		Config:   config,
		Metadata: new(Metadata),
		Exchange: new(Exchange),
		IQOSClient: &tsiq.IQOSClient{
			URL:          "hello",
			Quit:         make(chan bool),
			AuthResponse: new(tsiq.AuthResponse),
		},
		Nonce: "nothing yet",
		State: "application state",
	}
}

func (c *Client) GetMetadata() error {
	reqUrl := c.Config.Issuer + "/.well-known/openid-configuration"
	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("client_id", c.Config.ClientId)
	h.Add("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err := json.Unmarshal(body, c.Metadata); err != nil {
		return err
	}
	return nil
}

func (c *Client) GetAuthorizeURI(r *http.Request, uri string) string {
	c.Nonce, _ = util.GenerateNonce()
	c.State = util.EncodeBase64([]byte(uri))

	url := &url2.URL{}
	q := url.Query()
	q.Add("client_id", c.Config.ClientId)
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", c.Config.RedirectUri)
	q.Add("state", c.State)
	q.Add("nonce", c.Nonce)
	return c.Metadata.AuthorizationEndpoint + "?" + q.Encode()
}

func (c *Client) GetExchangeCode(code string, r *http.Request) error {
	authHeader := base64.StdEncoding.EncodeToString([]byte(c.Config.ClientId + ":" + c.Config.ClientSecret))
	q := r.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Add("code", code)
	q.Add("redirect_uri", c.Config.RedirectUri)

	exchangeUrl := c.Metadata.TokenEndpoint + "?" + q.Encode()
	req, _ := http.NewRequest("POST", exchangeUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err := json.Unmarshal(body, c.Exchange); err != nil {
		return err
	}

	// Verify JWT token
	if _, err := c.verifyToken(); err != nil {
		return err
	}

	// Fire IQOS here
	if err := c.IQOSClient.GetToken(); err != nil {
		return err
	}

	// Fire IQOS token refresher
	go c.IQOSClient.RefreshToken()

	return nil
}

func (c *Client) GetUserProfile(token string) (*UserProfile, error) {
	profile := new(UserProfile)

	reqUrl := c.Metadata.UserInfoEndpoint
	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))

	h := req.Header
	h.Add("Authorization", "Bearer "+token)
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err := json.Unmarshal(body, profile); err != nil {
		return nil, err
	}
	return profile, nil
}

func (c *Client) verifyToken() (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["nonce"] = c.Nonce
	tv["aud"] = c.Config.ClientId
	jv := verifier.JwtVerifier{
		Issuer:           c.Config.Issuer,
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(c.Exchange.IdToken)

	if err != nil {
		return nil, err
	}
	if result != nil {
		return result, nil
	}
	return nil, fmt.Errorf("token could not be verified: %s", "")
}

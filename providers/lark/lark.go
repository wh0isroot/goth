// Package gitlab implements the OAuth2 protocol for authenticating users through gitlab.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package lark

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"fmt"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// These vars define the Authentication, Token, and Profile URLS for Gitlab. If
// using Gitlab CE or EE, you should change these values before calling New.
//
// Examples:
//	gitlab.AuthURL = "https://gitlab.acme.com/oauth/authorize
//	gitlab.TokenURL = "https://gitlab.acme.com/oauth/token
//	gitlab.ProfileURL = "https://gitlab.acme.com/api/v3/user
var (
	AppAuthURL = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/"
	AuthURL    = "https://open.feishu.cn/open-apis/authen/v1/index"
	TokenURL   = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/"
	ProfileURL = "https://open.feishu.cn/open-apis/authen/v1/access_token"
)

// Provider is the implementation of `goth.Provider` for accessing Gitlab.
type Provider struct {
	ClientKey    string
	Secret       string
	AppToken     string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *Config
	providerName string
	appAuthURL   string
	authURL      string
	tokenURL     string
	profileURL   string
}

// New creates a new Gitlab provider and sets up important connection details.
// You should always call `gitlab.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, AuthURL, TokenURL, ProfileURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, profileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "gitlab",
		profileURL:   profileURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the lark package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks lark for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {

	b := struct {
		appID     string `json:"app_id"`
		appSecret string `jsob:"app_secret"`
	}{p.ClientKey, p.Secret}
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	r, err := p.Client().Post(AppAuthURL, "application/json", ioutil.NopCloser(bytes.NewReader(data)))
	if err != nil {
		return nil, err
	}
	u := struct {
		Code              int    `json:"code"`
		Msg               string `json:"msg"`
		AppAccessToken    string `json:"app_access_token"`
		Expire            int    `json:"expire"`
		TenantAccessToken string `json:"tenant_access_token"`
	}{}
	err = json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		return nil, err
	}
	p.config.AppToken = u.AppAccessToken
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to lark and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	response, err := p.Client().Get(p.profileURL + "?user_access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)

	return user, err
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *Config {
	c := &Config{
		AppID:       provider.ClientKey,
		AppSecret:   provider.Secret,
		RedirectURL: provider.CallbackURL,
		Endpoint: Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}
	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Data struct {
			Name      string `json:"name"`
			Email     string `json:"email"`
			ID        int    `json:"user_id"`
			AvatarURL string `json:"avatar_url"`
		} `json:"data"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.Email = u.Data.Email
	user.Name = u.Data.Name
	user.UserID = strconv.Itoa(u.Data.ID)
	user.AvatarURL = u.Data.AvatarURL
	return nil
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, nil
}

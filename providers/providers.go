package providers

import (
	"github.com/bitly/oauth2_proxy/cookie"
	"net/http"
)

type Provider interface {
	Data() *ProviderData
	GetEmailAddress(*SessionState) (string, error)
	GetUserName(*SessionState) (string, error)
	Redeem(string, string) (*SessionState, error)
	ValidateGroup(string) bool
	ValidateSessionState(*SessionState) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(*SessionState) (bool, error)
	SessionFromCookie(string, *cookie.Cipher) (*SessionState, error)
	CookieForSession(*SessionState, *cookie.Cipher) (string, error)
	ValidateRequest(*http.Request) (*SessionState, error)
}

func New(provider string, p *ProviderData) Provider {
	switch provider {
	case "linkedin":
		return NewLinkedInProvider(p)
	case "facebook":
		return NewFacebookProvider(p)
	case "github":
		return NewGitHubProvider(p)
	case "azure":
		return NewAzureProvider(p)
	case "gitlab":
		return NewGitLabProvider(p)
	case "oidc":
		return NewOIDCProvider(p)
	case "ping":
		return NewPingIdentityProvider(p)
	default:
		return NewGoogleProvider(p)
	}
}

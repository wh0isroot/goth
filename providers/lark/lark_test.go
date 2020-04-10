package lark_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wh0isroot/goth"
	"github.com/wh0isroot/goth/providers/lark"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, "cli_9e046e89522d500e")
	a.Equal(p.Secret, "6TEgs5Vhs52S8cOPSrEh4eOMXfa82XUz")
	a.Equal(p.CallbackURL, "/foo")
}

func Test_NewCustomisedURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := urlCustomisedURLProvider()
	session, err := p.BeginAuth("test_state")
	s := session.(*lark.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "http://authURL")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*lark.Session)

	a.NoError(err)
	a.Contains(s.AuthURL, "https://open.feishu.cn/open-apis/authen/v1/index")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://lark.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*lark.Session)
	a.Equal(s.AuthURL, "https://lark.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *lark.Provider {
	return lark.New("cli_9e046e89522d500e", "6TEgs5Vhs52S8cOPSrEh4eOMXfa82XUz", "https://127.0.0.1")
}

func urlCustomisedURLProvider() *lark.Provider {
	return lark.NewCustomisedURL(os.Getenv("lark_KEY"), os.Getenv("lark_SECRET"), "/foo", "http://authURL", "http://tokenURL", "http://profileURL")
}

// Package floauth performs an OAuth flow from a command-line application by opening a browser.
package floauth

// From https://github.com/nf/streak/blob/master/oauth.go

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

const (
	visitMessage  = "Visit the URL below to authenticate this program:"
	openedMessage = "Your browser has been opened to an authorization URL:"
	resumeMessage = "This program will resume once authenticated."
	closeMessage  = "You may now close this browser window."

	defaultAddr = "localhost:0"
)

type options struct {
	tok       *oauth2.Token
	addr      string
	filecache *TokenFileCache
	noBrowser bool
}

type Option func(o *options)

func WithNoBrowser() Option {
	return func(o *options) {
		o.noBrowser = true
	}
}

func WithExistingToken(tok *oauth2.Token) Option {
	return func(o *options) {
		o.tok = tok
	}
}

func WithTokenFileCache(name string) Option {
	c := NewTokenFileCache(name)
	return func(o *options) {
		o.filecache = c
	}
}

func WithFixedAddr(addr string) Option {
	return func(o *options) {
		o.addr = addr
	}
}

func processOpts(o []Option) *options {
	out := &options{}
	out.addr = defaultAddr
	for _, opt := range o {
		opt(out)
	}
	return out
}

func Client(ctx context.Context, config *oauth2.Config, options ...Option) (*http.Client, *oauth2.Token, error) {
	o := processOpts(options)
	if o.filecache != nil {
		tok, err := o.filecache.Token()
		if err == nil {
			o.tok = tok
		}
	}

	if o.tok != nil {
		tok, err := config.TokenSource(ctx, o.tok).Token()
		if err == nil {
			return config.Client(ctx, tok), tok, nil
		}
	}

	tok, err := ExecuteFlow(ctx, config, options...)
	if err != nil {
		return nil, nil, err
	}
	if o.filecache != nil {
		_ = o.filecache.Write(tok)
	}
	return config.Client(ctx, tok), tok, nil
}

func ExecuteFlow(ctx context.Context, config *oauth2.Config, options ...Option) (*oauth2.Token, error) {
	o := processOpts(options)

	configCopy := *config
	config = &configCopy

	code := make(chan string)

	l, err := net.Listen("tcp", o.addr)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	config.RedirectURL = fmt.Sprintf("http://%s/", l.Addr().String())

	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, closeMessage)
		code <- r.FormValue("code") // send code to OAuth flow
	}))

	url := config.AuthCodeURL("", oauth2.AccessTypeOffline)
	if o.noBrowser {
		fmt.Fprintln(os.Stderr, visitMessage)
	} else if err := openURL(url); err != nil {
		fmt.Fprintln(os.Stderr, visitMessage)
	} else {
		fmt.Fprintln(os.Stderr, openedMessage)
	}
	fmt.Fprintf(os.Stderr, "\n%s\n\n", url)
	fmt.Fprintln(os.Stderr, resumeMessage)

	return config.Exchange(ctx, <-code)
}

func openURL(url string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("Cannot open URL %s on this platform", url)
	}
	return err
}

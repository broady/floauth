package floauth

import (
	"encoding/gob"
	"os"

	"golang.org/x/oauth2"
)

func NewTokenFileCache(name string) *TokenFileCache {
	return &TokenFileCache{name}
}

type TokenFileCache struct {
	name string
}

func (c *TokenFileCache) Token() (*oauth2.Token, error) {
	f, err := os.Open(c.name)
	if err != nil {
		return nil, err
	}
	tok := new(oauth2.Token)
	if err := gob.NewDecoder(f).Decode(tok); err != nil {
		return nil, err
	}
	return tok, nil
}

func (c *TokenFileCache) Write(tok *oauth2.Token) error {
	f, err := os.Create(c.name)
	if err != nil {
		return err
	}
	defer f.Close()

	return gob.NewEncoder(f).Encode(tok)
}

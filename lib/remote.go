package lib

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/projectdiscovery/expirablelru"
	"golang.org/x/net/webdav"
)

type MountCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type MountPointConfig struct {
	UrlPrefix     string `json:"urlPrefix"`
	RootDirectory string `json:"rootDirectory"`
	ErrorMessage  string `json:"errorMessage"`
}

var authCache *expirablelru.Cache

func init() {
	authCache = expirablelru.NewExpirableLRU(1024, nil, time.Minute*10, time.Minute*30)
}

func getRemoteUser(auth_url string, username string, password string) (*User, error) {
	if auth_url != "" {
		cache_key := fmt.Sprintf("%s:%s", username, password)
		if authCache.Contains(cache_key) {
			value, ok := authCache.Get(cache_key)
			if ok {
				return value.(*User), nil
			}
		}
		credentials := MountCredentials{
			Username: username,
			Password: password,
		}
		req, err := json.Marshal(credentials)
		resp, err := http.Post(auth_url, "application/json", bytes.NewBuffer(req))
		if err != nil {
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, errors.New(fmt.Sprintf("Error: Non-OK HTTP status: %d", resp.StatusCode))
		}
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error reading response body: %s", err))
		}
		var mountConfig MountPointConfig
		err = json.Unmarshal(respBody, &mountConfig)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error unmarshalling response body: %s", err))
		}
		if mountConfig.ErrorMessage != "" {
			return nil, errors.New(mountConfig.ErrorMessage)
		}
		user := &User{
			Scope:  mountConfig.RootDirectory,
			Modify: true,
			Rules:  []*Rule{},
			Handler: &webdav.Handler{
				Prefix: mountConfig.UrlPrefix,
				FileSystem: WebDavDir{
					Dir:     webdav.Dir(mountConfig.RootDirectory),
					NoSniff: true,
				},
				LockSystem: webdav.NewMemLS(),
			},
		}
		authCache.AddWithTTL(cache_key, user, time.Minute*5)
		return user, nil
	} else {
		return nil, errors.New("Empty RemoteAuthUrl")
	}
}

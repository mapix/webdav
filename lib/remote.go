package lib

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/projectdiscovery/expirablelru"
	"go.uber.org/zap"

	redisLs "github.com/y805939188/go-webdav-redis-ls"
	"golang.org/x/net/webdav"
)

type MountCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Prefix   string `json:"prefix"`
}

type MountPointConfig struct {
	ReadOnly      bool   `json:"readonly"`
	AuthTTL       int    `json:"authTTL"`
	RootDirectory string `json:"rootDirectory"`
	ErrorMessage  string `json:"errorMessage"`
}

var authCache *expirablelru.Cache
var redisPool *redis.Pool

func init() {
	authCache = expirablelru.NewExpirableLRU(1024, nil, time.Minute*10, time.Minute*30)
	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")
	if redisHost == "" || redisPort == "" {
		panic("error: REDIS_HOST or REDIS_PORT not set")
	}
	redisUrl := fmt.Sprintf("%s:%s", redisHost, redisPort)
	redisPassword := os.Getenv("REDIS_PASSWORD")
	redisDB := os.Getenv("REDIS_DB")
	if redisPassword == "" {
		panic("error: REDIS_PASSWORD not set")
	}
	redisPool = &redis.Pool{
		Dial: func() (redis.Conn, error) {
			db, err := strconv.Atoi(redisDB)
			if err != nil {
				return nil, err
			}
			dialDB := redis.DialDatabase(db)
			c, err := redis.Dial("tcp", redisUrl, dialDB)
			if err != nil {
				return nil, err
			}
			if _, err := c.Do("AUTH", redisPassword); err != nil {
				c.Close()
				return nil, err
			} else {
				err = redisLs.ReleaseScript.Load(c)
				if err != nil {
					zap.S().Errorf("error loading release script: %s", err)
				}
				err = redisLs.CreateScript.Load(c)
				if err != nil {
					zap.S().Errorf("error loading create script: %s", err)
				}
				err = redisLs.ConfirmScript.Load(c)
				if err != nil {
					zap.S().Errorf("error loading confirm script: %s", err)
				}
				err = redisLs.RefreshScript.Load(c)
				if err != nil {
					zap.S().Errorf("error loading refresh script: %s", err)
				}
				err = redisLs.UnlockScript.Load(c)
				if err != nil {
					zap.S().Errorf("error loading unlock script: %s", err)
				}
			}
			return c, err
		},
	}
}

func getRemoteUser(auth_url string, username string, password string, urlPrefix string) (*User, error) {
	if auth_url != "" {
		cache_key := fmt.Sprintf("%s:%s:%s", username, password, urlPrefix)
		if authCache.Contains(cache_key) {
			value, ok := authCache.Get(cache_key)
			if ok {
				return value.(*User), nil
			}
		}
		credentials := MountCredentials{
			Username: username,
			Password: password,
			Prefix:   urlPrefix,
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

		if redisPool == nil {
			return nil, errors.New("redis pool not initialized")
		}
		// redisLs.CreateScript
		rls := redisLs.NewRedisLS(redisPool, "webdav:")

		user := &User{
			Scope:  mountConfig.RootDirectory,
			Modify: !mountConfig.ReadOnly,
			Rules:  []*Rule{},
			Handler: &webdav.Handler{
				Prefix: urlPrefix,
				FileSystem: WebDavDir{
					Dir:     webdav.Dir(mountConfig.RootDirectory),
					NoSniff: true,
				},
				Logger: func(r *http.Request, err error) {
					zap.L().Info("request: ", zap.String("method: ", r.Method), zap.String("url: ", r.URL.String()))
					if err != nil {
						zap.L().Error("err occurred: ", zap.String("error: ", err.Error()))
					} else {
						zap.L().Info("not error: ", zap.String("error: ", "nil"))
					}
				},
				LockSystem: rls,
			},
		}
		authCache.AddWithTTL(cache_key, user, time.Second*time.Duration(mountConfig.AuthTTL))
		return user, nil
	} else {
		return nil, errors.New("Empty RemoteAuthUrl")
	}
}

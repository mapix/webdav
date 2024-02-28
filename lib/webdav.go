package lib

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// CorsCfg is the CORS config.
type CorsCfg struct {
	Enabled        bool
	Credentials    bool
	AllowedHeaders []string
	AllowedHosts   []string
	AllowedMethods []string
	ExposedHeaders []string
}

// Config is the configuration of a WebDAV instance.
type Config struct {
	*User
	Auth                 bool
	RemoteAuth           bool
	RemoteAuthUrl        string
	RemoteAuthNPrefixSeg int
	Debug                bool
	NoSniff              bool
	Cors                 CorsCfg
	Users                map[string]*User
	LogFormat            string
}

func parseBearerAuth(auth string) (token string, ok bool) {
	const prefix = "Bearer "

	parts := strings.Split(auth, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", false
	}

	return parts[1], true
}

func BearerAuth(r *http.Request) (token string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	return parseBearerAuth(auth)
}

// ServeHTTP determines if the request is for this plugin, and if all prerequisites are met.
func (c *Config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u := c.User
	requestOrigin := r.Header.Get("Origin")

	// Add CORS headers before any operation so even on a 401 unauthorized status, CORS will work.
	if c.Cors.Enabled && requestOrigin != "" {
		headers := w.Header()

		allowedHeaders := strings.Join(c.Cors.AllowedHeaders, ", ")
		allowedMethods := strings.Join(c.Cors.AllowedMethods, ", ")
		exposedHeaders := strings.Join(c.Cors.ExposedHeaders, ", ")

		allowAllHosts := len(c.Cors.AllowedHosts) == 1 && c.Cors.AllowedHosts[0] == "*"
		allowedHost := isAllowedHost(c.Cors.AllowedHosts, requestOrigin)

		if allowAllHosts {
			headers.Set("Access-Control-Allow-Origin", "*")
		} else if allowedHost {
			headers.Set("Access-Control-Allow-Origin", requestOrigin)
		}

		if allowAllHosts || allowedHost {
			headers.Set("Access-Control-Allow-Headers", allowedHeaders)
			headers.Set("Access-Control-Allow-Methods", allowedMethods)

			if c.Cors.Credentials {
				headers.Set("Access-Control-Allow-Credentials", "true")
			}

			if len(c.Cors.ExposedHeaders) > 0 {
				headers.Set("Access-Control-Expose-Headers", exposedHeaders)
			}
		}
	}

	if r.Method == "OPTIONS" && c.Cors.Enabled && requestOrigin != "" {
		return
	}

	// Authentication
	if c.Auth {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

		// Gets the correct user for this request.
		username, password, ok := r.BasicAuth()
		token := ""
		zap.L().Info("login attempt", zap.String("username", username), zap.String("remote_address", r.RemoteAddr))
		if !ok {
			token, ok = BearerAuth(r)
			if !ok {
				http.Error(w, "Not authorized", 401)
				return
			}
		}

		user, ok := c.Users[username]
		if !ok {
			paths := strings.Split(r.URL.Path, "/")

			prefix := "/" + strings.Join(paths[1:c.RemoteAuthNPrefixSeg+1], "/")
			if token != "" {
				prefix += "/"
			}
			if c.RemoteAuth && len(paths) >= c.RemoteAuthNPrefixSeg {
				user, err := getRemoteUser(c.RemoteAuthUrl, token, username, password, prefix, r.URL.Path)
				if err != nil {
					http.Error(w, fmt.Sprintf("Not authorized : %s", err), 401)
					return
				} else {
					u = user
					zap.L().Info("user authorized from remote", zap.String("username", username))
				}
			} else {
				http.Error(w, "Not authorized", 401)
				return
			}
		} else {
			if !checkPassword(user.Password, password) {
				zap.L().Info("invalid password", zap.String("username", username), zap.String("remote_address", r.RemoteAddr))
				http.Error(w, "Not authorized", 401)
				return
			}

			u = user
			zap.L().Info("user authorized", zap.String("username", username))
		}
	} else {
		// Even if Auth is disabled, we might want to get
		// the user from the Basic Auth header. Useful for Caddy
		// plugin implementation.
		username, _, ok := r.BasicAuth()
		if ok {
			if user, ok := c.Users[username]; ok {
				u = user
			}
		}
	}

	// Checks for user permissions relatively to this PATH.
	noModification := r.Method == "GET" || r.Method == "HEAD" ||
		r.Method == "OPTIONS" || r.Method == "PROPFIND"

	allowed := u.Allowed(r.URL.Path, noModification)

	zap.L().Debug("allowed & method & path", zap.Bool("allowed", allowed), zap.String("method", r.Method), zap.String("path", r.URL.Path))

	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.Method == "HEAD" {
		w = newResponseWriterNoBody(w)
	}

	// Excerpt from RFC4918, section 9.4:
	//
	// 		GET, when applied to a collection, may return the contents of an
	//		"index.html" resource, a human-readable view of the contents of
	//		the collection, or something else altogether.
	//
	// Get, when applied to collection, will return the same as PROPFIND method.

	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, u.Handler.Prefix) {
		info, err := u.Handler.FileSystem.Stat(context.TODO(), strings.TrimPrefix(r.URL.Path, u.Handler.Prefix))
		if err == nil && info.IsDir() {
			r.Method = "PROPFIND"
			if r.Header.Get("Depth") == "" {
				r.Header.Add("Depth", "1")
			}
		}
	}

	// Runs the WebDAV.
	//u.Handler.LockSystem = webdav.NewMemLS()
	u.Handler.ServeHTTP(w, r)
}

// responseWriterNoBody is a wrapper used to suprress the body of the response
// to a request. Mainly used for HEAD requests.
type responseWriterNoBody struct {
	http.ResponseWriter
}

// newResponseWriterNoBody creates a new responseWriterNoBody.
func newResponseWriterNoBody(w http.ResponseWriter) *responseWriterNoBody {
	return &responseWriterNoBody{w}
}

// Header executes the Header method from the http.ResponseWriter.
func (w responseWriterNoBody) Header() http.Header {
	return w.ResponseWriter.Header()
}

// Write suprresses the body.
func (w responseWriterNoBody) Write(data []byte) (int, error) {
	return 0, nil
}

// WriteHeader writes the header to the http.ResponseWriter.
func (w responseWriterNoBody) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

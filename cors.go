package wcors

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type cors struct {
	allowAllOrigins  bool
	allowCredentials bool
	allowOriginFunc  func(string) bool
	allowOrigins     []string
	normalHeaders    http.Header
	preflightHeaders http.Header
	wildcardOrigins  [][]string
}

const (
	HttpSchema  = "http://"
	HttpsSchema = "https://"
	FileSchema  = "file://"
	WsSchema    = "ws://"
	WssSchema   = "wss://"

	Wildcard = "*"
)

var (
	DefaultSchemas = []string{
		HttpSchema,
		HttpsSchema,
	}
	ExtensionSchemas = []string{
		"chrome-extension://",
		"safari-extension://",
		"moz-extension://",
		"ms-browser-extension://",
	}
	FileSchemas = []string{
		FileSchema,
	}
	WebSocketSchemas = []string{
		WsSchema,
		WssSchema,
	}
)

func newCors(options Options) *cors {
	if err := options.Validate(); err != nil {
		panic(err.Error())
	}

	for _, origin := range options.allowOrigins {
		if origin == Wildcard {
			options.allowAllOrigins = true
		}
	}

	return &cors{
		allowOriginFunc:  options.allowOriginFunc,
		allowAllOrigins:  options.allowAllOrigins,
		allowCredentials: options.allowCredentials,
		allowOrigins:     normalize(options.allowOrigins),
		normalHeaders:    options.generateNormalHeaders(),
		preflightHeaders: options.generatePreflightHeaders(),
		wildcardOrigins:  options.parseWildcardRules(),
	}
}

func (cors *cors) applyCors(c *gin.Context) {
	origin := c.Request.Header.Get("Origin")
	if len(origin) == 0 {
		// request is not a CORS request
		return
	}
	host := c.Request.Host

	if origin == HttpSchema+host || origin == HttpsSchema+host {
		// request is not a CORS request but have origin header.
		// for example, use fetch api
		return
	}

	if !cors.validateOrigin(origin) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	if c.Request.Method == "OPTIONS" {
		cors.handlePreflight(c)
		defer c.AbortWithStatus(http.StatusNoContent) // Using 204 is better than 200 when the request status is OPTIONS
	} else {
		cors.handleNormal(c)
	}

	if !cors.allowAllOrigins {
		c.Header("Access-Control-Allow-Origin", origin)
	}
}

func (cors *cors) validateWildcardOrigin(origin string) bool {
	for _, w := range cors.wildcardOrigins {
		if w[0] == Wildcard && strings.HasSuffix(origin, w[1]) {
			return true
		}
		if w[1] == Wildcard && strings.HasPrefix(origin, w[0]) {
			return true
		}
		if strings.HasPrefix(origin, w[0]) && strings.HasSuffix(origin, w[1]) {
			return true
		}
	}

	return false
}

func (cors *cors) validateOrigin(origin string) bool {
	if cors.allowAllOrigins {
		return true
	}
	for _, value := range cors.allowOrigins {
		if value == origin {
			return true
		}
	}
	if len(cors.wildcardOrigins) > 0 && cors.validateWildcardOrigin(origin) {
		return true
	}
	if cors.allowOriginFunc != nil {
		return cors.allowOriginFunc(origin)
	}
	return false
}

func (cors *cors) handlePreflight(c *gin.Context) {
	header := c.Writer.Header()
	for key, value := range cors.preflightHeaders {
		header[key] = value
	}
}

func (cors *cors) handleNormal(c *gin.Context) {
	header := c.Writer.Header()
	for key, value := range cors.normalHeaders {
		header[key] = value
	}
}

// Default returns the location middleware with default configuration.
func Default() gin.HandlerFunc {
	return New(
		WithAllowMethods("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"),
		WithAllowHeaders("Origin", "Content-Length", "Content-Type"),
		WithAllowCredentials(false),
		WithMaxAge(12*time.Hour),
		WithAllowAllOrigins(true))
}

// New returns the location middleware with user-defined custom configuration.
func New(opts ...Option) gin.HandlerFunc {
	cors := newCors(newOptions(opts...))
	return func(c *gin.Context) {
		cors.applyCors(c)
	}
}

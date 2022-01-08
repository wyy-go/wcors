package wcors

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Option func(options *Options)

type AllowOriginFunc func(origin string) bool

type converter func(string) string

// Options represents all available options for the middleware.
type Options struct {
	allowAllOrigins bool

	// AllowOrigins is a list of origins a cross-domain request can be executed from.
	// If the special "*" value is present in the list, all origins will be allowed.
	// Default value is []
	allowOrigins []string

	// AllowOriginFunc is a custom function to validate the origin. It take the origin
	// as argument and returns true if allowed or false otherwise. If this option is
	// set, the content of AllowOrigins is ignored.
	allowOriginFunc func(origin string) bool

	// AllowMethods is a list of methods the client is allowed to use with
	// cross-domain requests. Default value is simple methods (GET and POST)
	allowMethods []string

	// AllowHeaders is list of non simple headers the client is allowed to use with
	// cross-domain requests.
	allowHeaders []string

	// AllowCredentials indicates whether the request can include user credentials like
	// cookies, HTTP authentication or client side SSL certificates.
	allowCredentials bool

	// ExposeHeaders indicates which headers are safe to expose to the API of a CORS
	// API specification
	exposeHeaders []string

	// MaxAge indicates how long (with second-precision) the results of a preflight request
	// can be cached
	maxAge time.Duration

	// Allows to add origins like http://some-domain/*, https://api.* or http://some.*.subdomain.com
	allowWildcard bool

	// Allows usage of popular browser extensions schemas
	allowBrowserExtensions bool

	// Allows usage of WebSocket protocol
	allowWebSockets bool

	// Allows usage of file:// schema (dangerous!) use it only when you 100% sure it's needed
	allowFiles bool
}

func WithAllowAllOrigins(allowAllOrigins bool) Option {
	return func(options *Options) {
		options.allowAllOrigins = allowAllOrigins
	}
}

func WithAllowOrigins(origins ...string) Option {
	return func(options *Options) {
		options.allowOrigins = append(options.allowOrigins, origins...)
	}
}

func WithAllowOriginFunc(allowOriginFunc AllowOriginFunc) Option {
	return func(options *Options) {
		options.allowOriginFunc = allowOriginFunc
	}
}

func WithAllowMethods(methods ...string) Option {
	return func(options *Options) {
		options.allowMethods = append(options.allowMethods, methods...)
	}
}

func WithAllowHeaders(headers ...string) Option {
	return func(options *Options) {
		options.allowHeaders = append(options.allowHeaders, headers...)
	}
}

func WithAllowCredentials(allowCredentials bool) Option {
	return func(options *Options) {
		options.allowCredentials = allowCredentials
	}
}

func WithExposeHeaders(headers ...string) Option {
	return func(options *Options) {
		options.exposeHeaders = append(options.exposeHeaders, headers...)
	}
}

func WithMaxAge(maxAge time.Duration) Option {
	return func(options *Options) {
		options.maxAge = maxAge
	}
}

func WithAllowWildcard(allowWildcard bool) Option {
	return func(options *Options) {
		options.allowWildcard = allowWildcard
	}
}

func WithAllowBrowserExtensions(allowBrowserExtensions bool) Option {
	return func(options *Options) {
		options.allowBrowserExtensions = allowBrowserExtensions
	}
}

func WithAllowWebSockets(allowWebSockets bool) Option {
	return func(options *Options) {
		options.allowWebSockets = allowWebSockets
	}
}

func WithAllowFiles(allowFiles bool) Option {
	return func(options *Options) {
		options.allowFiles = allowFiles
	}
}

func (c *Options) getAllowedSchemas() []string {
	allowedSchemas := DefaultSchemas
	if c.allowBrowserExtensions {
		allowedSchemas = append(allowedSchemas, ExtensionSchemas...)
	}
	if c.allowWebSockets {
		allowedSchemas = append(allowedSchemas, WebSocketSchemas...)
	}
	if c.allowFiles {
		allowedSchemas = append(allowedSchemas, FileSchemas...)
	}
	return allowedSchemas
}

func (c *Options) validateAllowedSchemas(origin string) bool {
	allowedSchemas := c.getAllowedSchemas()
	for _, schema := range allowedSchemas {
		if strings.HasPrefix(origin, schema) {
			return true
		}
	}
	return false
}

// Validate is check configuration of user defined.
func (c *Options) Validate() error {
	if c.allowAllOrigins && (c.allowOriginFunc != nil || len(c.allowOrigins) > 0) {
		return errors.New("conflict settings: all origins are allowed. AllowOriginFunc or AllowOrigins is not needed")
	}
	if !c.allowAllOrigins && c.allowOriginFunc == nil && len(c.allowOrigins) == 0 {
		return errors.New("conflict settings: all origins disabled")
	}
	for _, origin := range c.allowOrigins {
		if !strings.Contains(origin, "*") && !c.validateAllowedSchemas(origin) {
			return errors.New("bad origin: origins must contain '*' or include " + strings.Join(c.getAllowedSchemas(), ","))
		}
	}
	return nil
}

func (c *Options) parseWildcardRules() [][]string {
	var wRules [][]string

	if !c.allowWildcard {
		return wRules
	}

	for _, o := range c.allowOrigins {
		if !strings.Contains(o, "*") {
			continue
		}

		if c := strings.Count(o, "*"); c > 1 {
			panic(errors.New("only one * is allowed").Error())
		}

		i := strings.Index(o, "*")
		if i == 0 {
			wRules = append(wRules, []string{"*", o[1:]})
			continue
		}
		if i == (len(o) - 1) {
			wRules = append(wRules, []string{o[:i-1], "*"})
			continue
		}

		wRules = append(wRules, []string{o[:i], o[i+1:]})
	}

	return wRules
}

func (c *Options) generateNormalHeaders() http.Header {
	headers := make(http.Header)
	if c.allowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}
	if len(c.exposeHeaders) > 0 {
		exposeHeaders := convert(normalize(c.exposeHeaders), http.CanonicalHeaderKey)
		headers.Set("Access-Control-Expose-Headers", strings.Join(exposeHeaders, ","))
	}
	if c.allowAllOrigins {
		headers.Set("Access-Control-Allow-Origin", "*")
	} else {
		headers.Set("Vary", "Origin")
	}
	return headers
}

func (c *Options) generatePreflightHeaders() http.Header {
	headers := make(http.Header)
	if c.allowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}
	if len(c.allowMethods) > 0 {
		allowMethods := convert(normalize(c.allowMethods), strings.ToUpper)
		value := strings.Join(allowMethods, ",")
		headers.Set("Access-Control-Allow-Methods", value)
	}
	if len(c.allowHeaders) > 0 {
		allowHeaders := convert(normalize(c.allowHeaders), http.CanonicalHeaderKey)
		value := strings.Join(allowHeaders, ",")
		headers.Set("Access-Control-Allow-Headers", value)
	}
	if c.maxAge > time.Duration(0) {
		value := strconv.FormatInt(int64(c.maxAge/time.Second), 10)
		headers.Set("Access-Control-Max-Age", value)
	}
	if c.allowAllOrigins {
		headers.Set("Access-Control-Allow-Origin", "*")
	} else {
		// Always set Vary headers
		// see https://github.com/rs/cors/issues/10,
		// https://github.com/rs/cors/commit/dbdca4d95feaa7511a46e6f1efb3b3aa505bc43f#commitcomment-12352001

		headers.Add("Vary", "Origin")
		headers.Add("Vary", "Access-Control-Request-Method")
		headers.Add("Vary", "Access-Control-Request-Headers")
	}
	return headers
}

func normalize(values []string) []string {
	if values == nil {
		return nil
	}
	distinctMap := make(map[string]bool, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		value = strings.ToLower(value)
		if _, seen := distinctMap[value]; !seen {
			normalized = append(normalized, value)
			distinctMap[value] = true
		}
	}
	return normalized
}

func convert(s []string, c converter) []string {
	var out []string
	for _, i := range s {
		out = append(out, c(i))
	}
	return out
}

func newOptions(opts ...Option) Options {
	var options Options

	for _, opt := range opts {
		opt(&options)
	}
	return options
}

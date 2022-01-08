package wcors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestRouter(opts ...Option) *gin.Engine {
	router := gin.New()
	router.Use(New(opts...))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "get")
	})
	router.POST("/", func(c *gin.Context) {
		c.String(http.StatusOK, "post")
	})
	router.PATCH("/", func(c *gin.Context) {
		c.String(http.StatusOK, "patch")
	})
	return router
}

func performRequest(r http.Handler, method, origin string) *httptest.ResponseRecorder {
	return performRequestWithHeaders(r, method, origin, http.Header{})
}

func performRequestWithHeaders(r http.Handler, method, origin string, header http.Header) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, "/", nil)
	// From go/net/http/request.go:
	// For incoming requests, the Host header is promoted to the
	// Request.Host field and removed from the Header map.
	req.Host = header.Get("Host")
	header.Del("Host")
	if len(origin) > 0 {
		header.Set("Origin", origin)
	}
	req.Header = header
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestConfigAddAllow(t *testing.T) {
	options := newOptions(WithAllowMethods("POST"),
		WithAllowMethods("GET", "PUT"),
		WithExposeHeaders(),
		WithAllowHeaders("Some", " cool"),
		WithAllowHeaders("header"),
		WithExposeHeaders(),
		WithExposeHeaders(),
		WithExposeHeaders("exposed", "header"),
		WithExposeHeaders("hey"),
	)

	assert.Equal(t, options.allowMethods, []string{"POST", "GET", "PUT"})
	assert.Equal(t, options.allowHeaders, []string{"Some", " cool", "header"})
	assert.Equal(t, options.exposeHeaders, []string{"exposed", "header", "hey"})

}

func TestBadConfig(t *testing.T) {
	assert.Panics(t, func() { New() })
	assert.Panics(t, func() {
		New(WithAllowAllOrigins(true),
			WithAllowOrigins("http://google.com"))
	})
	assert.Panics(t, func() {
		New(WithAllowAllOrigins(true),
			WithAllowOriginFunc(func(origin string) bool {
				return false
			}),
		)
	})
	assert.Panics(t, func() {
		New(WithAllowOrigins("google.com"))
	})
}

func TestNormalize(t *testing.T) {
	values := normalize([]string{
		"http-Access ", "Post", "POST", " poSt  ",
		"HTTP-Access", "",
	})
	assert.Equal(t, values, []string{"http-access", "post", ""})

	values = normalize(nil)
	assert.Nil(t, values)

	values = normalize([]string{})
	assert.Equal(t, values, []string{})
}

func TestConvert(t *testing.T) {
	methods := []string{"Get", "GET", "get"}
	headers := []string{"X-CSRF-TOKEN", "X-CSRF-Token", "x-csrf-token"}

	assert.Equal(t, []string{"GET", "GET", "GET"}, convert(methods, strings.ToUpper))
	assert.Equal(t, []string{"X-Csrf-Token", "X-Csrf-Token", "X-Csrf-Token"}, convert(headers, http.CanonicalHeaderKey))
}

func TestGenerateNormalHeaders_AllowAllOrigins(t *testing.T) {
	options := newOptions(WithAllowAllOrigins(false))

	header := options.generateNormalHeaders()
	assert.Equal(t, header.Get("Access-Control-Allow-Origin"), "")
	assert.Equal(t, header.Get("Vary"), "Origin")
	assert.Len(t, header, 1)

	options = newOptions(WithAllowAllOrigins(true))
	header = options.generateNormalHeaders()
	assert.Equal(t, header.Get("Access-Control-Allow-Origin"), "*")
	assert.Equal(t, header.Get("Vary"), "")
	assert.Len(t, header, 1)
}

func TestGenerateNormalHeaders_AllowCredentials(t *testing.T) {
	options := newOptions(WithAllowCredentials(true))

	header := options.generateNormalHeaders()
	assert.Equal(t, header.Get("Access-Control-Allow-Credentials"), "true")
	assert.Equal(t, header.Get("Vary"), "Origin")
	assert.Len(t, header, 2)
}

func TestGenerateNormalHeaders_ExposedHeaders(t *testing.T) {
	options := newOptions(WithExposeHeaders("X-user", "xPassword"))

	header := options.generateNormalHeaders()
	assert.Equal(t, header.Get("Access-Control-Expose-Headers"), "X-User,Xpassword")
	assert.Equal(t, header.Get("Vary"), "Origin")
	assert.Len(t, header, 2)
}

func TestGeneratePreflightHeaders(t *testing.T) {
	options := newOptions(WithAllowAllOrigins(false))

	header := options.generatePreflightHeaders()
	assert.Equal(t, header.Get("Access-Control-Allow-Origin"), "")
	assert.Equal(t, header.Get("Vary"), "Origin")
	assert.Len(t, header, 1)

	options = newOptions(WithAllowAllOrigins(true))
	header = options.generateNormalHeaders()
	assert.Equal(t, header.Get("Access-Control-Allow-Origin"), "*")
	assert.Equal(t, header.Get("Vary"), "")
	assert.Len(t, header, 1)
}

func TestGeneratePreflightHeaders_AllowCredentials(t *testing.T) {
	options := newOptions(WithAllowCredentials(true))

	header := options.generatePreflightHeaders()
	assert.Equal(t, header.Get("Access-Control-Allow-Credentials"), "true")
	assert.Equal(t, header.Get("Vary"), "Origin")
	assert.Len(t, header, 2)
}

func TestGeneratePreflightHeaders_AllowMethods(t *testing.T) {
	options := newOptions(WithAllowMethods("GET ", "post", "PUT", " put  "))

	header := options.generatePreflightHeaders()
	assert.Equal(t, header.Get("Access-Control-Allow-Methods"), "GET,POST,PUT")
	assert.Equal(t, header.Get("Vary"), "Origin")
	assert.Len(t, header, 2)
}

func TestGeneratePreflightHeaders_AllowHeaders(t *testing.T) {
	options := newOptions(WithAllowHeaders("X-user", "Content-Type"))

	header := options.generatePreflightHeaders()
	assert.Equal(t, header.Get("Access-Control-Allow-Headers"), "X-User,Content-Type")
	assert.Equal(t, header.Get("Vary"), "Origin")
	assert.Len(t, header, 2)
}

func TestGeneratePreflightHeaders_MaxAge(t *testing.T) {
	options := newOptions(WithMaxAge(12 * time.Hour))

	header := options.generatePreflightHeaders()
	assert.Equal(t, header.Get("Access-Control-Max-Age"), "43200") // 12*60*60
	assert.Equal(t, header.Get("Vary"), "Origin")
	assert.Len(t, header, 2)
}

func TestValidateOrigin(t *testing.T) {
	cors := newCors(newOptions(WithAllowAllOrigins(true)))
	assert.True(t, cors.validateOrigin("http://google.com"))
	assert.True(t, cors.validateOrigin("https://google.com"))
	assert.True(t, cors.validateOrigin("example.com"))
	assert.True(t, cors.validateOrigin("chrome-extension://random-extension-id"))

	cors = newCors(newOptions(
		WithAllowOrigins("https://google.com", "https://github.com"),
		WithAllowOriginFunc(func(origin string) bool {
			return origin == "http://news.ycombinator.com"
		}),
		WithAllowBrowserExtensions(true)),
	)
	assert.False(t, cors.validateOrigin("http://google.com"))
	assert.True(t, cors.validateOrigin("https://google.com"))
	assert.True(t, cors.validateOrigin("https://github.com"))
	assert.True(t, cors.validateOrigin("http://news.ycombinator.com"))
	assert.False(t, cors.validateOrigin("http://example.com"))
	assert.False(t, cors.validateOrigin("google.com"))
	assert.False(t, cors.validateOrigin("chrome-extension://random-extension-id"))

	cors = newCors(newOptions(WithAllowOrigins("https://google.com", "https://github.com")))
	assert.False(t, cors.validateOrigin("chrome-extension://random-extension-id"))
	assert.False(t, cors.validateOrigin("file://some-dangerous-file.js"))
	assert.False(t, cors.validateOrigin("wss://socket-connection"))

	cors = newCors(newOptions(WithAllowOrigins("chrome-extension://*", "safari-extension://my-extension-*-app", "*.some-domain.com"),
		WithAllowBrowserExtensions(true),
		WithAllowWildcard(true)))

	assert.True(t, cors.validateOrigin("chrome-extension://random-extension-id"))
	assert.True(t, cors.validateOrigin("chrome-extension://another-one"))
	assert.True(t, cors.validateOrigin("safari-extension://my-extension-one-app"))
	assert.True(t, cors.validateOrigin("safari-extension://my-extension-two-app"))
	assert.False(t, cors.validateOrigin("moz-extension://ext-id-we-not-allow"))
	assert.True(t, cors.validateOrigin("http://api.some-domain.com"))
	assert.False(t, cors.validateOrigin("http://api.another-domain.com"))

	cors = newCors(newOptions(WithAllowOrigins("file://safe-file.js", "wss://some-session-layer-connection"),
		WithAllowFiles(true),
		WithAllowWebSockets(true)))

	assert.True(t, cors.validateOrigin("file://safe-file.js"))
	assert.False(t, cors.validateOrigin("file://some-dangerous-file.js"))
	assert.True(t, cors.validateOrigin("wss://some-session-layer-connection"))
	assert.False(t, cors.validateOrigin("ws://not-what-we-expected"))

	cors = newCors(newOptions(WithAllowOrigins("*")))
	assert.True(t, cors.validateOrigin("http://google.com"))
	assert.True(t, cors.validateOrigin("https://google.com"))
	assert.True(t, cors.validateOrigin("example.com"))
	assert.True(t, cors.validateOrigin("chrome-extension://random-extension-id"))
}

func TestPassesAllowOrigins(t *testing.T) {
	router := newTestRouter(
		WithAllowOrigins("http://google.com"),
		WithAllowMethods(" GeT ", "get", "post", "PUT  ", "Head", "POST"),
		WithAllowHeaders("Content-type", "timeStamp "),
		WithExposeHeaders("Data", "x-User"),
		WithAllowCredentials(false),
		WithMaxAge(12*time.Hour),
		WithAllowOriginFunc(func(origin string) bool {
			return origin == "http://github.com"
		}))

	// no CORS request, origin == ""
	w := performRequest(router, "GET", "")
	assert.Equal(t, "get", w.Body.String())
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Empty(t, w.Header().Get("Access-Control-Expose-Headers"))

	// no CORS request, origin == host
	h := http.Header{}
	h.Set("Host", "facebook.com")
	w = performRequestWithHeaders(router, "GET", "http://facebook.com", h)
	assert.Equal(t, "get", w.Body.String())
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Empty(t, w.Header().Get("Access-Control-Expose-Headers"))

	// allowed CORS request
	w = performRequest(router, "GET", "http://google.com")
	assert.Equal(t, "get", w.Body.String())
	assert.Equal(t, "http://google.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "Data,X-User", w.Header().Get("Access-Control-Expose-Headers"))

	w = performRequest(router, "GET", "http://github.com")
	assert.Equal(t, "get", w.Body.String())
	assert.Equal(t, "http://github.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "Data,X-User", w.Header().Get("Access-Control-Expose-Headers"))

	// deny CORS request
	w = performRequest(router, "GET", "https://google.com")
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Empty(t, w.Header().Get("Access-Control-Expose-Headers"))

	// allowed CORS prefligh request
	w = performRequest(router, "OPTIONS", "http://github.com")
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://github.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "GET,POST,PUT,HEAD", w.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type,Timestamp", w.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "43200", w.Header().Get("Access-Control-Max-Age"))

	// deny CORS prefligh request
	w = performRequest(router, "OPTIONS", "http://example.com")
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Methods"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Headers"))
	assert.Empty(t, w.Header().Get("Access-Control-Max-Age"))
}

func TestPassesAllowAllOrigins(t *testing.T) {
	router := newTestRouter(
		WithAllowAllOrigins(true),
		WithAllowMethods(" Patch ", "get", "post", "POST"),
		WithAllowHeaders("Content-type", "  testheader "),
		WithExposeHeaders("Data2", "x-User2"),
		WithAllowCredentials(false),
		WithMaxAge(10*time.Hour))

	// no CORS request, origin == ""
	w := performRequest(router, "GET", "")
	assert.Equal(t, "get", w.Body.String())
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Empty(t, w.Header().Get("Access-Control-Expose-Headers"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))

	// allowed CORS request
	w = performRequest(router, "POST", "example.com")
	assert.Equal(t, "post", w.Body.String())
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "Data2,X-User2", w.Header().Get("Access-Control-Expose-Headers"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))

	// allowed CORS prefligh request
	w = performRequest(router, "OPTIONS", "https://facebook.com")
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "PATCH,GET,POST", w.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type,Testheader", w.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "36000", w.Header().Get("Access-Control-Max-Age"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))

}

func TestWildcard(t *testing.T) {
	router := newTestRouter(
		WithAllowOrigins("https://*.github.com", "https://api.*", "http://*", "https://facebook.com", "*.golang.org"),
		WithAllowMethods("GET"),
		WithAllowWildcard(true))

	w := performRequest(router, "GET", "https://gist.github.com")
	assert.Equal(t, 200, w.Code)

	w = performRequest(router, "GET", "https://api.github.com/v1/users")
	assert.Equal(t, 200, w.Code)

	w = performRequest(router, "GET", "https://giphy.com/")
	assert.Equal(t, 403, w.Code)

	w = performRequest(router, "GET", "http://hard-to-find-http-example.com")
	assert.Equal(t, 200, w.Code)

	w = performRequest(router, "GET", "https://facebook.com")
	assert.Equal(t, 200, w.Code)

	w = performRequest(router, "GET", "https://something.golang.org")
	assert.Equal(t, 200, w.Code)

	w = performRequest(router, "GET", "https://something.go.org")
	assert.Equal(t, 403, w.Code)

	router = newTestRouter(
		WithAllowOrigins("https://github.com", "https://facebook.com"),
		WithAllowMethods("GET"))

	w = performRequest(router, "GET", "https://gist.github.com")
	assert.Equal(t, 403, w.Code)

	w = performRequest(router, "GET", "https://github.com")
	assert.Equal(t, 200, w.Code)
}

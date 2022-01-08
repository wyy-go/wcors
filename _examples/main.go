package main

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wyy-go/wcors"
)

func main() {
	router := gin.Default()
	// CORS for https://foo.com and https://github.com origins, allowing:
	// - PUT and PATCH methods
	// - Origin header
	// - Credentials share
	// - Preflight requests cached for 12 hours
	router.Use(wcors.New(
		wcors.WithAllowOrigins("https://foo.com"),
		wcors.WithAllowMethods("PUT", "PATCH"),
		wcors.WithAllowHeaders("Origin"),
		wcors.WithExposeHeaders("Content-Length"),
		wcors.WithAllowCredentials( true),
		wcors.WithAllowOriginFunc( func(origin string) bool {
			return origin == "https://github.com"
		}),
		wcors.WithMaxAge(12 * time.Hour),
	))
	router.Run()
}

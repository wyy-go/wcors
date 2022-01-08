# wcors

![GitHub Repo stars](https://img.shields.io/github/stars/wyy-go/wcors?style=social)
![GitHub](https://img.shields.io/github/license/wyy-go/wcors)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/wyy-go/wcors)
![GitHub CI Status](https://img.shields.io/github/workflow/status/wyy-go/wcors/ci?label=CI)
[![Go Report Card](https://goreportcard.com/badge/github.com/wyy-go/wcors)](https://goreportcard.com/report/github.com/wyy-go/wcors)
[![Go.Dev reference](https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white)](https://pkg.go.dev/github.com/wyy-go/wcors?tab=doc)
[![codecov](https://codecov.io/gh/wyy-go/wcors/branch/main/graph/badge.svg)](https://codecov.io/gh/wyy-go/wcors)


Gin middleware/handler to enable CORS support.

## Usage

### Start using it

Download and install it:

```sh
go get github.com/wyy-go/wcors
```

Import it in your code:

```go
import "github.com/wyy-go/wcors"
```

### Canonical example

```go
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
```
package nest_test

import (
	"github.com/gin-gonic/gin"
	"github.com/securityresearchlab/nebula-est/nest_service/pkg/models"
)

const (
	NEST = iota
	CA
	CONFIG
)

func MockRouterForEndpoint(endpoint *models.Route) *gin.Engine {
	router := gin.Default()
	switch endpoint.Method {
	case "GET":
		router.GET(endpoint.Pattern, endpoint.HandlerFunc)
	case "POST":
		router.POST(endpoint.Pattern, endpoint.HandlerFunc)
	}

	return router
}

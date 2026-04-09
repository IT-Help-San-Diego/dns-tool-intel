package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestShouldServeAsyncWait_GET_NoSync(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com", nil)

	if !shouldServeAsyncWait(c, nil, false) {
		t.Error("expected true for plain GET without sync=1")
	}
}

func TestShouldServeAsyncWait_GET_Sync1(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&sync=1", nil)

	if shouldServeAsyncWait(c, nil, false) {
		t.Error("expected false when sync=1 is set")
	}
}

func TestShouldServeAsyncWait_POST(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/analyze?domain=example.com", nil)

	if shouldServeAsyncWait(c, nil, false) {
		t.Error("expected false for POST requests")
	}
}

func TestShouldServeAsyncWait_FetchHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com", nil)
	c.Request.Header.Set("X-Requested-With", "fetch")

	if shouldServeAsyncWait(c, nil, false) {
		t.Error("expected false when X-Requested-With: fetch is set")
	}
}

func TestShouldServeAsyncWait_AgentCacheEligible(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&src=agent", nil)

	if shouldServeAsyncWait(c, nil, false) {
		t.Error("expected false for agent-cache-eligible requests")
	}
}

func TestShouldServeAsyncWait_CustomSelectorsNotAgent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com", nil)

	if !shouldServeAsyncWait(c, []string{"sel1"}, false) {
		t.Error("expected true: custom selectors without src=agent should still serve async wait")
	}
}

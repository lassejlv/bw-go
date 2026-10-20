package serve

import (
	"net/http"
	"net/url"
	"strings"
)

// router reproduces the matching rules of @koa/router (path-to-regexp with the router defaults):
// paths match case-insensitively, a trailing slash is optional, named parameters match one
// non-empty segment and are URL-decoded. Matched parameters are exposed through the Go 1.22
// request API (r.PathValue). router.allowedMethods() is reproduced in serveFallback.
type router struct {
	routes []*route
}

type route struct {
	method   string
	pattern  string
	segments []string // literal segment, or ":name"
	handler  http.HandlerFunc
}

// implementedMethods are @koa/router's default `methods`.
var implementedMethods = []string{"HEAD", "OPTIONS", "GET", "PUT", "PATCH", "POST", "DELETE"}

func (rt *router) handle(method, pattern string, h http.HandlerFunc) {
	rt.routes = append(rt.routes, &route{
		method:   method,
		pattern:  pattern,
		segments: strings.Split(strings.TrimPrefix(pattern, "/"), "/"),
		handler:  h,
	})
}

// methods are the methods a route answers to; koa-router adds HEAD to GET routes.
func (r *route) methods() []string {
	if r.method == http.MethodGet {
		return []string{http.MethodHead, http.MethodGet}
	}
	return []string{r.method}
}

// match reports whether the escaped request path matches the route and returns its parameters.
func (r *route) match(escapedPath string) (map[string]string, bool) {
	p := strings.TrimPrefix(escapedPath, "/")
	p = strings.TrimSuffix(p, "/") // strict: false
	parts := strings.Split(p, "/")
	if len(parts) != len(r.segments) {
		return nil, false
	}
	var params map[string]string
	for i, seg := range r.segments {
		if name, ok := strings.CutPrefix(seg, ":"); ok {
			if parts[i] == "" {
				return nil, false
			}
			v, err := url.PathUnescape(parts[i])
			if err != nil {
				v = parts[i] // safeDecodeURIComponent keeps undecodable text
			}
			if params == nil {
				params = map[string]string{}
			}
			params[name] = v
			continue
		}
		if !strings.EqualFold(seg, parts[i]) {
			return nil, false
		}
	}
	return params, true
}

func (rt *router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	var allowed []string
	for _, rte := range rt.routes {
		params, ok := rte.match(path)
		if !ok {
			continue
		}
		for _, m := range rte.methods() {
			if !contains(allowed, m) {
				allowed = append(allowed, m)
			}
		}
		if contains(rte.methods(), r.Method) {
			for k, v := range params {
				r.SetPathValue(k, v)
			}
			rte.handler(w, r)
			return
		}
	}
	serveFallback(w, r, allowed)
}

// serveFallback mirrors router.allowedMethods() followed by koa's default 404 response.
func serveFallback(w http.ResponseWriter, r *http.Request, allowed []string) {
	allow := strings.Join(allowed, ", ")
	switch {
	case !contains(implementedMethods, r.Method):
		w.Header().Set("Allow", allow)
		writeText(w, http.StatusNotImplemented, "Not Implemented")
	case len(allowed) > 0 && r.Method == http.MethodOptions:
		w.Header().Set("Allow", allow)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
	case len(allowed) > 0:
		w.Header().Set("Allow", allow)
		writeText(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	default:
		writeText(w, http.StatusNotFound, "Not Found")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// writeText writes a koa default (status message) text body.
func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

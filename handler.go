/*
Copyright 2025 Pextra Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package pextra_license_auth

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "endpoint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Endpoint = d.Val()
			case "product_id":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.ProductID = d.Val()
			case "cache_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				m.CacheTtl = dur
			default:
				return d.Errf("unknown option: %s", d.Val())
			}
		}
	}

	if !strings.Contains(m.Endpoint, "{license}") {
		return d.Errf("endpoint must contain '{license}' placeholder")
	}
	return nil
}

var licensePattern = regexp.MustCompile(`^[A-Za-z0-9\-]{6,}-V\d$`)

func ret401(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="License Required"`)
	w.WriteHeader(http.StatusUnauthorized)
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	_, password, ok := parseBasicAuth(r)
	if !ok || !licensePattern.MatchString(password) {
		m.logger.Debug("Could not extract properly-formatted license key from request")
		ret401(w)
		return nil
	}

	if valid, found := m.cache.Get(password); found {
		if valid {
			m.logger.Debug("Found valid license key in cache, serving request")
			return next.ServeHTTP(w, r)
		} else {
			m.logger.Debug("Found invalid license key in cache, returning 401")
			ret401(w)
			return nil
		}
	}

	valid, err := m.validateLicense(password)
	if err != nil {
		m.logger.Debug("Error validating license key", zap.Error(err))
		ret401(w)
		return nil
	}

	m.cache.Add(password, valid)
	if valid {
		m.logger.Debug("License key is valid, serving request")
		return next.ServeHTTP(w, r)
	}

	m.logger.Debug("License key is invalid, returning 401")
	ret401(w)
	return nil
}

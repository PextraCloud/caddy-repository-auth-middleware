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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

// Export middleware to Caddy
var _ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
var _ caddy.Provisioner = (*Middleware)(nil)
var _ caddyfile.Unmarshaler = (*Middleware)(nil)

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.pextra_license_auth",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.logger.Debug("Provisioning middleware")
	m.cache = expirable.NewLRU[string, bool](1000, nil, m.CacheTtl)

	return nil
}

// Register module and unmarshal Caddyfile
func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("pextra_license_auth", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler,
		error) {
		m := new(Middleware)
		if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
			return nil, err
		}
		return m, nil
	})
}

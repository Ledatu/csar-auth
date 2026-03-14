package session

import (
	"encoding/json"
	"net/http"

	"github.com/ledatu/csar-core/jwtx"
)

// JWKSHandler returns an http.Handler that serves the JWKS endpoint.
func JWKSHandler(mgr *Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kp := mgr.Keys()

		jwk, err := jwtx.NewJWKFromPublicKey(kp.PublicKey, kp.KID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		jwks := jwtx.JWKS{Keys: []jwtx.JWK{*jwk}}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store")
		_ = json.NewEncoder(w).Encode(jwks)
	})
}

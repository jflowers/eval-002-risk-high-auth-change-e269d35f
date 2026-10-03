package auth

import (
    "context"
    "net/http"
)

// Handler validates requests against the configured auth provider.
func Handler(provider string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            token := r.Header.Get("Authorization")
            if token == "" {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
            if !validateToken(r.Context(), token, provider) {
                http.Error(w, "forbidden", http.StatusForbidden)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

func validateToken(ctx context.Context, token, provider string) bool {
    switch provider {
    case "oidc":
        _, err := oidcVerifier.Verify(ctx, token)
        return err == nil
    case "static":
        return constantTimeEqual(token, staticToken)
    default:
        return false
    }
}


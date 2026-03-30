package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

const permSessionsRead = "platform.sessions.read"

func (h *Handler) requireSessionsReadPermission(r *http.Request, subject string) *apierror.Response {
	resp, err := h.authzClient.client.CheckAccess(r.Context(), &pb.CheckAccessRequest{
		Subject:   subject,
		ScopeType: "platform",
		Resource:  "admin",
		Action:    permSessionsRead,
	})
	if err != nil {
		h.logger.Error("authz check failed", "subject", subject, "error", err)
		return apierror.New("authz_error", http.StatusBadGateway, "authorization check failed")
	}
	if !resp.Allowed {
		return apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "insufficient permissions")
	}
	return nil
}

type sessionListItem struct {
	SessionID  string `json:"session_id"`
	UserID     string `json:"user_id"`
	Email      string `json:"email,omitempty"`
	CreatedAt  int64  `json:"created_at"`
	LastSeenAt int64  `json:"last_seen_at"`
	ExpiresAt  int64  `json:"expires_at"`
	UserAgent  string `json:"user_agent"`
	IPAddress  string `json:"ip_address"`
	RevokedAt  *int64 `json:"revoked_at,omitempty"`
	IsActive   bool   `json:"is_active"`
	IsCurrent  bool   `json:"is_current,omitempty"`
}

type sessionListResponse struct {
	Sessions []sessionListItem `json:"sessions"`
}

func safeSessionID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:8])
}

func sessionToItem(sess store.Session, email string, now time.Time, currentSessionID string) sessionListItem {
	item := sessionListItem{
		SessionID:  safeSessionID(sess.ID),
		UserID:     sess.UserID.String(),
		Email:      email,
		CreatedAt:  sess.CreatedAt.Unix(),
		LastSeenAt: sess.LastSeenAt.Unix(),
		ExpiresAt:  sess.ExpiresAt.Unix(),
		UserAgent:  sess.UserAgent,
		IPAddress:  sess.IPAddress,
		IsActive:   sess.RevokedAt == nil && now.Before(sess.ExpiresAt),
	}
	if currentSessionID != "" && sess.ID == currentSessionID {
		item.IsCurrent = true
	}
	if sess.RevokedAt != nil {
		ts := sess.RevokedAt.Unix()
		item.RevokedAt = &ts
	}
	return item
}

func (h *Handler) bearerClaims(r *http.Request) (string, *session.Claims) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", nil
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if token == "" {
		return "", nil
	}
	claims, err := h.sessionMgr.VerifyToken(token)
	if err != nil {
		return "", nil
	}
	return token, claims
}

func writeSessionListResponse(w http.ResponseWriter, sessions []sessionListItem) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Authorization, Cookie")
	_ = json.NewEncoder(w).Encode(sessionListResponse{Sessions: sessions})
}

func (h *Handler) handleListAdminSessions(w http.ResponseWriter, r *http.Request) {
	subject := h.extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if apiErr := h.requireSessionsReadPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	var userFilter *uuid.UUID
	if q := r.URL.Query().Get("user_id"); q != "" {
		uid, err := uuid.Parse(q)
		if err != nil {
			apierror.New("bad_request", http.StatusBadRequest, "invalid user_id").Write(w)
			return
		}
		userFilter = &uid
	}

	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			apierror.New("bad_request", http.StatusBadRequest, "invalid limit").Write(w)
			return
		}
		limit = n
	}
	if limit > 500 {
		limit = 500
	}

	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			apierror.New("bad_request", http.StatusBadRequest, "invalid offset").Write(w)
			return
		}
		offset = n
	}

	activeOnly := false
	if v := r.URL.Query().Get("active_only"); v != "" {
		switch v {
		case "1", "true", "yes":
			activeOnly = true
		case "0", "false", "no":
			activeOnly = false
		default:
			apierror.New("bad_request", http.StatusBadRequest, "invalid active_only").Write(w)
			return
		}
	}

	rows, err := h.store.ListAdminSessions(r.Context(), store.AdminSessionListParams{
		UserID:     userFilter,
		Limit:      limit,
		Offset:     offset,
		ActiveOnly: activeOnly,
	})
	if err != nil {
		h.logger.Error("failed to list admin sessions", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list sessions").Write(w)
		return
	}

	now := time.Now().UTC()
	out := make([]sessionListItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, sessionToItem(row.Session, row.UserEmail, now, ""))
	}

	writeSessionListResponse(w, out)
}

func (h *Handler) handleMeSessions(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	sessions, err := h.store.ListUserSessions(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("failed to list user sessions", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list sessions").Write(w)
		return
	}

	var currentID string
	if sess != nil {
		currentID = sess.ID
	}
	now := time.Now().UTC()
	out := make([]sessionListItem, 0, len(sessions))
	for i := range sessions {
		out = append(out, sessionToItem(sessions[i], user.Email, now, currentID))
	}
	if sess == nil && len(out) == 0 {
		if token, claims := h.bearerClaims(r); claims != nil {
			out = append(out, sessionListItem{
				SessionID:  safeSessionID(token),
				UserID:     user.ID.String(),
				Email:      user.Email,
				CreatedAt:  claims.Iat,
				LastSeenAt: now.Unix(),
				ExpiresAt:  claims.Exp,
				UserAgent:  r.UserAgent(),
				IsActive:   claims.Exp > now.Unix(),
				IsCurrent:  true,
			})
		}
	}

	writeSessionListResponse(w, out)
}

package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

const (
	permSessionsRead   = "platform.sessions.read"
	permSessionsRevoke = "platform.sessions.revoke"
)

func (h *Handler) requireSessionsReadPermission(r *http.Request, subject string) *apierror.Response {
	return h.requireSessionsPermission(r, subject, permSessionsRead)
}

func (h *Handler) requireSessionsRevokePermission(r *http.Request, subject string) *apierror.Response {
	return h.requireSessionsPermission(r, subject, permSessionsRevoke)
}

func (h *Handler) requireSessionsPermission(r *http.Request, subject, action string) *apierror.Response {
	resp, err := h.authzClient.client.CheckAccess(r.Context(), &pb.CheckAccessRequest{
		Subject:   subject,
		ScopeType: "platform",
		Resource:  "admin",
		Action:    action,
	})
	if err != nil {
		h.logger.Error("authz check failed", "subject", subject, "action", action, "error", err)
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
	Sessions   []sessionListItem     `json:"sessions"`
	Pagination sessionListPagination `json:"pagination"`
}

type sessionListPagination struct {
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"has_more"`
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

func writeSessionListResponse(w http.ResponseWriter, sessions []sessionListItem, limit, offset int, hasMore bool) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Authorization, Cookie")
	_ = json.NewEncoder(w).Encode(sessionListResponse{
		Sessions: sessions,
		Pagination: sessionListPagination{
			Limit:   limit,
			Offset:  offset,
			HasMore: hasMore,
		},
	})
}

func (h *Handler) findUserSessionBySafeID(ctx context.Context, userID uuid.UUID, safeID string) (*store.Session, error) {
	sessions, err := h.store.ListUserSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	for i := range sessions {
		if safeSessionID(sessions[i].ID) == safeID {
			sess := sessions[i]
			return &sess, nil
		}
	}
	return nil, store.ErrNotFound
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

	status := "all"
	if v := strings.TrimSpace(r.URL.Query().Get("status")); v != "" {
		status = strings.ToLower(v)
		switch status {
		case "all", "active", "revoked", "expired":
		default:
			apierror.New("bad_request", http.StatusBadRequest, "invalid status").Write(w)
			return
		}
	} else if v := r.URL.Query().Get("active_only"); v != "" {
		switch v {
		case "1", "true", "yes":
			status = "active"
		case "0", "false", "no":
			status = "all"
		default:
			apierror.New("bad_request", http.StatusBadRequest, "invalid active_only").Write(w)
			return
		}
	}

	emailFilter := strings.TrimSpace(r.URL.Query().Get("email"))

	rows, hasMore, err := h.store.ListAdminSessions(r.Context(), store.AdminSessionListParams{
		UserID: userFilter,
		Email:  emailFilter,
		Status: status,
		Limit:  limit,
		Offset: offset,
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

	writeSessionListResponse(w, out, limit, offset, hasMore)
}

func (h *Handler) handleRevokeAdminSession(w http.ResponseWriter, r *http.Request) {
	subject := h.extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if apiErr := h.requireSessionsRevokePermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	adminSessionID := strings.TrimSpace(r.PathValue("session_id"))
	if adminSessionID == "" {
		apierror.New("bad_request", http.StatusBadRequest, "session_id is required").Write(w)
		return
	}

	row, err := h.store.RevokeAdminSession(r.Context(), adminSessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "session not found or already inactive").Write(w)
			return
		}
		h.logger.Error("failed to revoke admin session", "session_id", adminSessionID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to revoke session").Write(w)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"session_id": adminSessionID,
		"user_id":    row.UserID.String(),
		"email":      row.UserEmail,
		"revoked_at": row.RevokedAt.Unix(),
	})
	h.recordAudit(r, subject, "session.revoke", "session", adminSessionID, afterJSON)

	w.WriteHeader(http.StatusNoContent)
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

	writeSessionListResponse(w, out, len(out), 0, false)
}

func (h *Handler) handleRevokeMeSession(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	sessionID := strings.TrimSpace(r.PathValue("session_id"))
	if sessionID == "" {
		apierror.New("bad_request", http.StatusBadRequest, "session_id is required").Write(w)
		return
	}

	target, err := h.findUserSessionBySafeID(r.Context(), user.ID, sessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "session not found").Write(w)
			return
		}
		h.logger.Error("failed to resolve user session", "user_id", user.ID, "session_id", sessionID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to revoke session").Write(w)
		return
	}

	if err := h.sessMgr.Revoke(r.Context(), target.ID); err != nil {
		h.logger.Error("failed to revoke user session", "user_id", user.ID, "session_id", sessionID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to revoke session").Write(w)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"session_id": sessionID,
		"user_id":    user.ID.String(),
		"revoked_at": time.Now().UTC().Unix(),
	})
	h.recordAudit(r, user.ID.String(), "session.self_revoke", "session", sessionID, afterJSON)

	if sess != nil && target.ID == sess.ID {
		http.SetCookie(w, h.sessionCookie("", -1))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleRevokeOtherMeSessions(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	sessions, err := h.store.ListUserSessions(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("failed to list user sessions for revoke others", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to revoke sessions").Write(w)
		return
	}

	currentID := ""
	if sess != nil {
		currentID = sess.ID
	}

	revokedCount := 0
	for i := range sessions {
		if currentID != "" && sessions[i].ID == currentID {
			continue
		}
		if err := h.sessMgr.Revoke(r.Context(), sessions[i].ID); err != nil {
			h.logger.Error("failed to revoke other user session", "user_id", user.ID, "session_id", safeSessionID(sessions[i].ID), "error", err)
			apierror.New("internal_error", http.StatusInternalServerError, "failed to revoke sessions").Write(w)
			return
		}
		revokedCount++
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"user_id":       user.ID.String(),
		"current_kept":  currentID != "",
		"revoked_count": revokedCount,
	})
	h.recordAudit(r, user.ID.String(), "session.revoke_others", "user", user.ID.String(), afterJSON)

	w.WriteHeader(http.StatusNoContent)
}

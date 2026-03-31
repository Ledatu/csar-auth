package handler

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/audit"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

const permServiceAccountsManage = "platform.service_accounts.manage"

func (h *Handler) requireSAPermission(r *http.Request, subject string) *apierror.Response {
	resp, err := h.authzClient.client.CheckAccess(r.Context(), &pb.CheckAccessRequest{
		Subject:   subject,
		ScopeType: "platform",
		Resource:  "admin",
		Action:    permServiceAccountsManage,
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

func (h *Handler) recordAudit(r *http.Request, actor, action, targetType, targetID string, afterState json.RawMessage) {
	if h.auditRecorder == nil {
		return
	}
	event := &audit.Event{
		Actor:      actor,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		ScopeType:  "platform",
		AfterState: afterState,
	}
	if err := h.auditRecorder.Record(r.Context(), event); err != nil {
		h.logger.Warn("failed to record audit event", "action", action, "error", err)
	}
}

func (h *Handler) reloadSTS(r *http.Request) error {
	if h.stsHandler == nil {
		return nil
	}
	if err := h.stsHandler.Reload(r.Context()); err != nil {
		h.logger.Error("failed to reload STS after SA mutation", "error", err)
		return err
	}
	return nil
}

// --- Response types ---

type saResponse struct {
	Name              string   `json:"name"`
	AllowedAudiences  []string `json:"allowed_audiences"`
	AllowAllAudiences bool     `json:"allow_all_audiences,omitempty"`
	TokenTTL          string   `json:"token_ttl"`
	Status            string   `json:"status"`
	CreatedAt         int64    `json:"created_at"`
	RotatedAt         *int64   `json:"rotated_at,omitempty"`
	RevokedAt         *int64   `json:"revoked_at,omitempty"`
}

type saDetailResponse struct {
	saResponse
	PublicKeyPEM string `json:"public_key_pem"`
}

func saToResponse(sa *store.ServiceAccount) saResponse {
	resp := saResponse{
		Name:              sa.Name,
		AllowedAudiences:  sa.AllowedAudiences,
		AllowAllAudiences: sa.AllowAllAudiences,
		TokenTTL:          sa.TokenTTL.String(),
		Status:            sa.Status,
		CreatedAt:         sa.CreatedAt.Unix(),
	}
	if sa.RotatedAt != nil {
		ts := sa.RotatedAt.Unix()
		resp.RotatedAt = &ts
	}
	if sa.RevokedAt != nil {
		ts := sa.RevokedAt.Unix()
		resp.RevokedAt = &ts
	}
	return resp
}

// --- Handlers ---

func (h *Handler) handleListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	subject := h.extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	if apiErr := h.requireSAPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	accounts, err := h.store.ListActiveServiceAccounts(r.Context())
	if err != nil {
		h.logger.Error("failed to list service accounts", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list service accounts").Write(w)
		return
	}

	resp := make([]saResponse, len(accounts))
	for i, sa := range accounts {
		resp[i] = saToResponse(&sa)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

type createSARequest struct {
	Name              string   `json:"name"`
	PublicKeyPEM      string   `json:"public_key_pem"`
	AllowedAudiences  []string `json:"allowed_audiences"`
	AllowAllAudiences bool     `json:"allow_all_audiences"`
	TokenTTL          string   `json:"token_ttl"`
}

func (h *Handler) handleCreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	subject := h.extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	if apiErr := h.requireSAPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	var body createSARequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		apierror.New("bad_request", http.StatusBadRequest, "request body must contain name").Write(w)
		return
	}
	if body.PublicKeyPEM == "" {
		apierror.New("bad_request", http.StatusBadRequest, "public_key_pem is required").Write(w)
		return
	}
	if len(body.AllowedAudiences) == 0 && !body.AllowAllAudiences {
		apierror.New("bad_request", http.StatusBadRequest, "allowed_audiences is required (or set allow_all_audiences)").Write(w)
		return
	}

	if err := validatePEM(body.PublicKeyPEM); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid public key PEM: "+err.Error()).Write(w)
		return
	}

	ttl := time.Hour
	if body.TokenTTL != "" {
		parsed, err := time.ParseDuration(body.TokenTTL)
		if err != nil {
			apierror.New("bad_request", http.StatusBadRequest, "invalid token_ttl: "+err.Error()).Write(w)
			return
		}
		ttl = parsed
	}

	sa := &store.ServiceAccount{
		Name:              body.Name,
		PublicKeyPEM:      body.PublicKeyPEM,
		AllowedAudiences:  body.AllowedAudiences,
		AllowAllAudiences: body.AllowAllAudiences,
		TokenTTL:          ttl,
		Status:            "active",
	}

	if err := h.store.CreateServiceAccount(r.Context(), sa); err != nil {
		h.logger.Error("failed to create service account", "name", body.Name, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create service account").Write(w)
		return
	}

	if err := h.reloadSTS(r); err != nil {
		apierror.New("reload_failed", http.StatusInternalServerError, "service account persisted but live reload failed").Write(w)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"name":                sa.Name,
		"allowed_audiences":   sa.AllowedAudiences,
		"allow_all_audiences": sa.AllowAllAudiences,
		"token_ttl":           sa.TokenTTL.String(),
	})
	h.recordAudit(r, subject, "service_account.create", "service_account", sa.Name, afterJSON)

	resp := saToResponse(sa)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleGetServiceAccount(w http.ResponseWriter, r *http.Request) {
	subject := h.extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	if apiErr := h.requireSAPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	name := r.PathValue("name")
	if name == "" {
		apierror.New("bad_request", http.StatusBadRequest, "service account name is required").Write(w)
		return
	}

	sa, err := h.store.GetServiceAccount(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "service account not found").Write(w)
			return
		}
		h.logger.Error("failed to get service account", "name", name, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to get service account").Write(w)
		return
	}

	resp := saDetailResponse{
		saResponse:   saToResponse(sa),
		PublicKeyPEM: sa.PublicKeyPEM,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleRevokeServiceAccount(w http.ResponseWriter, r *http.Request) {
	subject := h.extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	if apiErr := h.requireSAPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	name := r.PathValue("name")
	if name == "" {
		apierror.New("bad_request", http.StatusBadRequest, "service account name is required").Write(w)
		return
	}

	if err := h.store.RevokeServiceAccount(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "service account not found or already revoked").Write(w)
			return
		}
		h.logger.Error("failed to revoke service account", "name", name, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to revoke service account").Write(w)
		return
	}

	if err := h.reloadSTS(r); err != nil {
		apierror.New("reload_failed", http.StatusInternalServerError, "service account persisted but live reload failed").Write(w)
		return
	}

	h.recordAudit(r, subject, "service_account.revoke", "service_account", name, nil)

	w.WriteHeader(http.StatusNoContent)
}

type rotateSARequest struct {
	PublicKeyPEM string `json:"public_key_pem"`
}

func (h *Handler) handleRotateServiceAccount(w http.ResponseWriter, r *http.Request) {
	subject := h.extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	if apiErr := h.requireSAPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	name := r.PathValue("name")
	if name == "" {
		apierror.New("bad_request", http.StatusBadRequest, "service account name is required").Write(w)
		return
	}

	var body rotateSARequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PublicKeyPEM == "" {
		apierror.New("bad_request", http.StatusBadRequest, "public_key_pem is required").Write(w)
		return
	}

	if err := validatePEM(body.PublicKeyPEM); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid public key PEM: "+err.Error()).Write(w)
		return
	}

	if err := h.store.UpdateServiceAccountKey(r.Context(), name, body.PublicKeyPEM); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "service account not found or not active").Write(w)
			return
		}
		h.logger.Error("failed to rotate service account key", "name", name, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to rotate key").Write(w)
		return
	}

	if err := h.reloadSTS(r); err != nil {
		apierror.New("reload_failed", http.StatusInternalServerError, "service account persisted but live reload failed").Write(w)
		return
	}

	h.recordAudit(r, subject, "service_account.rotate", "service_account", name, nil)

	w.WriteHeader(http.StatusNoContent)
}

func validatePEM(pemStr string) error {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return errors.New("no PEM block found")
	}
	_, err := x509.ParsePKIXPublicKey(block.Bytes)
	return err
}

package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/markbates/goth/gothic"

	"github.com/ledatu/csar-core/audit"

	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

// handleMergeInitiate starts the merge OAuth flow. The user must be
// authenticated (session cookie proves target user). We store merge
// state in the Goth session and redirect to the OAuth provider.
func (h *Handler) handleMergeInitiate(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if provider == "" {
		http.Error(w, "missing provider", http.StatusBadRequest)
		return
	}

	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	// Set provider in query so Goth can find it.
	q := r.URL.Query()
	q.Set("provider", provider)
	r.URL.RawQuery = q.Encode()

	// Store merge state in Goth session.
	if err := gothic.StoreInSession("intent", "merge", r, w); err != nil {
		h.logger.Error("failed to store merge intent", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := gothic.StoreInSession("merge_target", user.ID.String(), r, w); err != nil {
		h.logger.Error("failed to store merge_target", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		h.logger.Error("failed to generate merge nonce", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonceHex := hex.EncodeToString(nonce)
	if err := gothic.StoreInSession("merge_nonce", nonceHex, r, w); err != nil {
		h.logger.Error("failed to store merge_nonce", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("initiating merge OAuth flow",
		"target_user", user.ID, "provider", provider,
	)

	gothic.BeginAuthHandler(w, r)
}

// handleMerge executes the merge after the user has completed the
// re-authentication flow. Validates session cookie (target) and
// csar_merge cookie (proves source ownership).
func (h *Handler) handleMerge(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}
	targetID := user.ID

	// Read the merge cookie.
	mergeCookie, err := r.Cookie("csar_merge")
	if err != nil {
		http.Error(w, "missing merge credential", http.StatusBadRequest)
		return
	}

	// Hash the raw token to look up the record.
	hash := sha256.Sum256([]byte(mergeCookie.Value))
	tokenHash := hex.EncodeToString(hash[:])

	// Atomically consume the merge record.
	rec, err := h.store.ConsumeMergeRecord(r.Context(), tokenHash, targetID)
	if err != nil {
		h.logger.Warn("merge record consumption failed",
			"target_user", targetID, "error", err,
		)
		http.Error(w, "merge token invalid, expired, or already used", http.StatusBadRequest)
		return
	}

	sourceID := rec.SourceUser

	// Execute the authn-side merge.
	if err := h.store.MergeUsers(r.Context(), targetID, sourceID); err != nil {
		h.logger.Error("merge failed",
			"target_user", targetID, "source_user", sourceID, "error", err,
		)
		http.Error(w, "merge failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.logger.Info("authn merge completed",
		"target_user", targetID, "source_user", sourceID,
	)

	// Audit the merge event.
	if h.auditStore != nil {
		meta := json.RawMessage(fmt.Sprintf(`{"source_user":%q,"target_user":%q}`, sourceID, targetID))
		_ = h.auditStore.Record(r.Context(), &audit.Event{
			Actor:      targetID.String(),
			Action:     "user.merged",
			TargetType: "user",
			TargetID:   sourceID.String(),
			Metadata:   meta,
		})
	}

	// Attempt authz reassignment (idempotent, retryable).
	authzOK := h.reassignAuthzSubject(r, sourceID.String(), targetID.String())
	if authzOK {
		if err := h.store.MarkMergeAuthzComplete(r.Context(), rec.ID); err != nil {
			h.logger.Warn("failed to mark authz complete", "record_id", rec.ID, "error", err)
		}
	} else {
		h.logger.Warn("authz reassignment failed — will retry later",
			"record_id", rec.ID, "source", sourceID, "target", targetID,
		)
	}

	// Clear the merge cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "csar_merge",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"merged":         true,
		"source_user":    sourceID.String(),
		"target_user":    targetID.String(),
		"authz_complete": authzOK,
	})
}

// reassignAuthzSubject calls the authz gRPC service to move all
// assignments from source to target. Returns true on success.
func (h *Handler) reassignAuthzSubject(r *http.Request, source, target string) bool {
	if h.authzClient == nil {
		return true
	}

	ctx := r.Context()
	logger := h.logger.With(slog.String("source", source), slog.String("target", target))

	_, err := h.authzClient.client.ReassignSubject(ctx, &pb.ReassignSubjectRequest{
		SourceSubject: source,
		TargetSubject: target,
	})
	if err != nil {
		logger.Error("authz ReassignSubject RPC failed", "error", err)
		return false
	}

	logger.Info("authz subject reassignment completed")
	return true
}

// RunMergeAuthzReconciler periodically retries pending authz reassignments
// that failed during the original merge. Blocks until ctx is cancelled.
func (h *Handler) RunMergeAuthzReconciler(ctx context.Context, interval time.Duration) {
	if h.authzClient == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.reconcilePendingAuthzMerges(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (h *Handler) reconcilePendingAuthzMerges(ctx context.Context) {
	recs, err := h.store.GetPendingAuthzMerges(ctx)
	if err != nil {
		h.logger.Error("failed to fetch pending authz merges", "error", err)
		return
	}
	for _, rec := range recs {
		_, err := h.authzClient.client.ReassignSubject(ctx, &pb.ReassignSubjectRequest{
			SourceSubject: rec.SourceUser.String(),
			TargetSubject: rec.TargetUser.String(),
		})
		if err != nil {
			h.logger.Warn("authz reconcile failed",
				"record_id", rec.ID, "source", rec.SourceUser, "target", rec.TargetUser, "error", err,
			)
			continue
		}
		if err := h.store.MarkMergeAuthzComplete(ctx, rec.ID); err != nil {
			h.logger.Warn("failed to mark authz complete after reconcile",
				"record_id", rec.ID, "error", err,
			)
			continue
		}
		h.logger.Info("authz reconcile succeeded",
			"record_id", rec.ID, "source", rec.SourceUser, "target", rec.TargetUser,
		)
	}
}

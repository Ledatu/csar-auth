package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/pgutil"
)

func (s *Store) ListActiveServiceAccounts(ctx context.Context) ([]store.ServiceAccount, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT name, public_key_pem, allowed_audiences, allow_all_audiences,
		        token_ttl, status, created_at, rotated_at, revoked_at
		 FROM service_accounts WHERE status = 'active'
		 ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing active service accounts: %w", err)
	}
	defer rows.Close()

	var accounts []store.ServiceAccount
	for rows.Next() {
		var sa store.ServiceAccount
		var ttl time.Duration
		if err := rows.Scan(&sa.Name, &sa.PublicKeyPEM, &sa.AllowedAudiences,
			&sa.AllowAllAudiences, &ttl, &sa.Status, &sa.CreatedAt,
			&sa.RotatedAt, &sa.RevokedAt); err != nil {
			return nil, fmt.Errorf("scanning service account: %w", err)
		}
		sa.TokenTTL = ttl
		accounts = append(accounts, sa)
	}
	return accounts, rows.Err()
}

func (s *Store) GetServiceAccount(ctx context.Context, name string) (*store.ServiceAccount, error) {
	var sa store.ServiceAccount
	var ttl time.Duration
	err := s.pool.QueryRow(ctx,
		`SELECT name, public_key_pem, allowed_audiences, allow_all_audiences,
		        token_ttl, status, created_at, rotated_at, revoked_at
		 FROM service_accounts WHERE name = $1`, name,
	).Scan(&sa.Name, &sa.PublicKeyPEM, &sa.AllowedAudiences,
		&sa.AllowAllAudiences, &ttl, &sa.Status, &sa.CreatedAt,
		&sa.RotatedAt, &sa.RevokedAt)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get service account: %w", err)
	}
	sa.TokenTTL = ttl
	return &sa, nil
}

func (s *Store) CreateServiceAccount(ctx context.Context, sa *store.ServiceAccount) error {
	now := time.Now()
	sa.CreatedAt = now
	if sa.Status == "" {
		sa.Status = "active"
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO service_accounts
		 (name, public_key_pem, allowed_audiences, allow_all_audiences, token_ttl, status, created_at)
		 VALUES ($1, $2, $3, $4, $5::interval, $6, $7)`,
		sa.Name, sa.PublicKeyPEM, sa.AllowedAudiences,
		sa.AllowAllAudiences, fmt.Sprintf("%d seconds", int(sa.TokenTTL.Seconds())),
		sa.Status, sa.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create service account: %w", err)
	}
	return nil
}

func (s *Store) UpdateServiceAccountKey(ctx context.Context, name, newPEM string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE service_accounts
		 SET public_key_pem = $2, rotated_at = now()
		 WHERE name = $1 AND status = 'active'`,
		name, newPEM,
	)
	if err != nil {
		return fmt.Errorf("update service account key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) RevokeServiceAccount(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE service_accounts
		 SET status = 'revoked', revoked_at = now()
		 WHERE name = $1 AND status = 'active'`,
		name,
	)
	if err != nil {
		return fmt.Errorf("revoke service account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

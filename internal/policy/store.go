package policy

import (
    "database/sql"
    "time"
    _ "github.com/lib/pq"
)

type PolicyChange struct {
    Epoch      int64
    TenantID   string
    ChangeType string // "url_rule" | "auth_policy"
    Payload    []byte // JSON
    CreatedAt  time.Time
}

type Store struct {
    db *sql.DB
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) CurrentEpoch(tenantID string) (int64, error) {
    var epoch int64
    err := s.db.QueryRow(
        `SELECT COALESCE(MAX(epoch), 0) FROM policy_changes WHERE tenant_id = $1`,
        tenantID,
    ).Scan(&epoch)
    return epoch, err
}

// Delta returns all changes between fromEpoch (exclusive) and toEpoch (inclusive).
// ZEN nodes call this when they detect drift via the reconciler.
func (s *Store) Delta(tenantID string, fromEpoch, toEpoch int64) ([]PolicyChange, error) {
    rows, err := s.db.Query(`
        SELECT epoch, tenant_id, change_type, payload, created_at
        FROM policy_changes
        WHERE tenant_id = $1 AND epoch > $2 AND epoch <= $3
        ORDER BY epoch ASC`,
        tenantID, fromEpoch, toEpoch,
    )
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var changes []PolicyChange
    for rows.Next() {
        var c PolicyChange
        if err := rows.Scan(&c.Epoch, &c.TenantID, &c.ChangeType, &c.Payload, &c.CreatedAt); err != nil {
            return nil, err
        }
        changes = append(changes, c)
    }
    return changes, rows.Err()
}

func (s *Store) AppendChange(tenantID, changeType string, payload []byte) (int64, error) {
    var epoch int64
    err := s.db.QueryRow(`
        INSERT INTO policy_changes (tenant_id, change_type, payload, created_at)
        VALUES ($1, $2, $3, NOW())
        RETURNING epoch`,
        tenantID, changeType, payload,
    ).Scan(&epoch)
    return epoch, err
}

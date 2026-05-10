package policy

// PolicySnapshot is a minimal proto-like struct for snapshots.
type PolicySnapshot struct {
    TenantID string
    Epoch    int64
    Payload  []byte
}

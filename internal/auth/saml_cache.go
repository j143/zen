package auth

import (
    "context"
    "crypto/sha256"
    "encoding/json"
    "errors"
    "fmt"
    "sync/atomic"
    "time"

    "github.com/redis/go-redis/v9"
)

var ErrAssertionExpired = errors.New("saml assertion already expired")

type SAMLSession struct {
    UserID      string    `json:"user_id"`
    Groups      []string  `json:"groups"`
    PolicyEpoch int64     `json:"policy_epoch"`
    ExpiresAt   time.Time `json:"expires_at"`
    IdPEntityID string    `json:"idp_entity_id"`
}

type SAMLCache struct {
    rdb          *redis.Client
    currentEpoch atomic.Int64
}

func NewSAMLCache(rdb *redis.Client, epoch int64) *SAMLCache {
    c := &SAMLCache{rdb: rdb}
    c.currentEpoch.Store(epoch)
    return c
}

func (c *SAMLCache) UpdateEpoch(epoch int64) {
    c.currentEpoch.Store(epoch)
}

func cacheKey(nameID, sessionIdx, idpEntity string) string {
    h := sha256.Sum256([]byte(nameID + "|" + sessionIdx + "|" + idpEntity))
    return fmt.Sprintf("saml:session:%x", h)
}

func userIndexKey(userID string) string {
    return fmt.Sprintf("saml:user:%s", userID)
}

func (c *SAMLCache) Set(ctx context.Context, nameID, sessionIdx string, sess SAMLSession) error {
    ttl := time.Until(sess.ExpiresAt)
    if ttl <= 0 {
        return ErrAssertionExpired
    }
    key := cacheKey(nameID, sessionIdx, sess.IdPEntityID)
    data, err := json.Marshal(sess)
    if err != nil {
        return err
    }
    pipe := c.rdb.Pipeline()
    pipe.Set(ctx, key, data, ttl)
    // reverse index for O(1) user invalidation
    pipe.SAdd(ctx, userIndexKey(sess.UserID), key)
    pipe.Expire(ctx, userIndexKey(sess.UserID), ttl)
    _, err = pipe.Exec(ctx)
    return err
}

func (c *SAMLCache) Get(ctx context.Context, nameID, sessionIdx, idpEntity string) (*SAMLSession, bool) {
    key := cacheKey(nameID, sessionIdx, idpEntity)
    val, err := c.rdb.Get(ctx, key).Bytes()
    if err == redis.Nil {
        return nil, false
    }
    if err != nil {
        return nil, false
    }
    var sess SAMLSession
    if err := json.Unmarshal(val, &sess); err != nil {
        return nil, false
    }
    // Stale policy check: if epoch advanced, force re-auth
    if sess.PolicyEpoch < c.currentEpoch.Load() {
        c.rdb.Del(ctx, key)
        return nil, false
    }
    return &sess, true
}

// InvalidateUser removes all cached sessions for a SCIM-deprovisioned user. O(1) via reverse index.
func (c *SAMLCache) InvalidateUser(ctx context.Context, userID string) error {
    idxKey := userIndexKey(userID)
    keys, err := c.rdb.SMembers(ctx, idxKey).Result()
    if err != nil {
        return err
    }
    if len(keys) == 0 {
        return nil
    }
    pipe := c.rdb.Pipeline()
    pipe.Del(ctx, keys...)
    pipe.Del(ctx, idxKey)
    _, err = pipe.Exec(ctx)
    return err
}

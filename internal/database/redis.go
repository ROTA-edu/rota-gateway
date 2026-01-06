package database

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisConfig holds Redis connection configuration
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int // Redis database number (0-15)

	// Connection pool settings
	PoolSize     int
	MinIdleConns int
	MaxRetries   int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Redis wraps a go-redis client
type Redis struct {
	Client *redis.Client
	config RedisConfig
}

// NewRedis creates a new Redis client
func NewRedis(cfg RedisConfig) (*Redis, error) {
	// Set defaults
	if cfg.PoolSize == 0 {
		cfg.PoolSize = 10
	}
	if cfg.MinIdleConns == 0 {
		cfg.MinIdleConns = 5
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 3 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 3 * time.Second
	}

	// Create Redis client
	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		MaxRetries:   cfg.MaxRetries,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	// Ping Redis to verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping redis: %w", err)
	}

	return &Redis{
		Client: client,
		config: cfg,
	}, nil
}

// Close closes the Redis client
func (r *Redis) Close() error {
	if r.Client != nil {
		return r.Client.Close()
	}
	return nil
}

// Ping verifies the Redis connection is alive
func (r *Redis) Ping(ctx context.Context) error {
	return r.Client.Ping(ctx).Err()
}

// Health returns Redis health status
func (r *Redis) Health(ctx context.Context) error {
	// Check connection
	if err := r.Ping(ctx); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}

	// Check pool stats
	stats := r.Client.PoolStats()
	if stats.TotalConns == 0 {
		return fmt.Errorf("no connections in pool")
	}

	return nil
}

// Stats returns connection pool statistics
func (r *Redis) Stats() *redis.PoolStats {
	return r.Client.PoolStats()
}

// Set stores a key-value pair with optional TTL
func (r *Redis) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return r.Client.Set(ctx, key, value, ttl).Err()
}

// Get retrieves a value by key
func (r *Redis) Get(ctx context.Context, key string) (string, error) {
	return r.Client.Get(ctx, key).Result()
}

// Del deletes one or more keys
func (r *Redis) Del(ctx context.Context, keys ...string) error {
	return r.Client.Del(ctx, keys...).Err()
}

// Exists checks if a key exists
func (r *Redis) Exists(ctx context.Context, key string) (bool, error) {
	count, err := r.Client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Expire sets a TTL on an existing key
func (r *Redis) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return r.Client.Expire(ctx, key, ttl).Err()
}

// SetNX sets a key-value pair only if the key does not exist (atomic)
func (r *Redis) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	return r.Client.SetNX(ctx, key, value, ttl).Result()
}

// Incr increments a counter (atomic)
func (r *Redis) Incr(ctx context.Context, key string) (int64, error) {
	return r.Client.Incr(ctx, key).Result()
}

// IncrBy increments a counter by a specific amount (atomic)
func (r *Redis) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	return r.Client.IncrBy(ctx, key, value).Result()
}

// SAdd adds members to a set
func (r *Redis) SAdd(ctx context.Context, key string, members ...interface{}) error {
	return r.Client.SAdd(ctx, key, members...).Err()
}

// SMembers returns all members of a set
func (r *Redis) SMembers(ctx context.Context, key string) ([]string, error) {
	return r.Client.SMembers(ctx, key).Result()
}

// SRem removes members from a set
func (r *Redis) SRem(ctx context.Context, key string, members ...interface{}) error {
	return r.Client.SRem(ctx, key, members...).Err()
}

// TTL returns the remaining time to live of a key
func (r *Redis) TTL(ctx context.Context, key string) (time.Duration, error) {
	return r.Client.TTL(ctx, key).Result()
}

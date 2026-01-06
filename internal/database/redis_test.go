package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedisConfig_Valid tests creating a Redis connection with valid config
func TestRedisConfig_Valid(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := RedisConfig{
		Host: "localhost",
		Port: 6379,
		DB:   0,
	}

	rdb, err := NewRedis(cfg)
	require.NoError(t, err, "NewRedis should not error with valid config")
	require.NotNil(t, rdb, "Redis instance should not be nil")
	defer rdb.Close()

	// Verify connection works
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = rdb.Ping(ctx)
	assert.NoError(t, err, "Ping should succeed")
}

// TestRedisConfig_InvalidHost tests connection with invalid host
func TestRedisConfig_InvalidHost(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := RedisConfig{
		Host: "invalid-host-that-does-not-exist",
		Port: 6379,
		DB:   0,
	}

	_, err := NewRedis(cfg)
	assert.Error(t, err, "NewRedis should error with invalid host")
}

// TestRedisHealth tests the Health check
func TestRedisHealth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := RedisConfig{
		Host: "localhost",
		Port: 6379,
		DB:   0,
	}

	rdb, err := NewRedis(cfg)
	require.NoError(t, err)
	defer rdb.Close()

	ctx := context.Background()
	err = rdb.Health(ctx)
	assert.NoError(t, err, "Health check should pass")

	// Check stats
	stats := rdb.Stats()
	assert.NotNil(t, stats, "Stats should not be nil")
}

// TestRedisSetGet tests Set and Get operations
func TestRedisSetGet(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := RedisConfig{
		Host: "localhost",
		Port: 6379,
		DB:   0,
	}

	rdb, err := NewRedis(cfg)
	require.NoError(t, err)
	defer rdb.Close()

	ctx := context.Background()

	// Set a value
	key := "test:key:1"
	value := "test-value"
	err = rdb.Set(ctx, key, value, 10*time.Second)
	assert.NoError(t, err, "Set should succeed")

	// Get the value
	result, err := rdb.Get(ctx, key)
	assert.NoError(t, err, "Get should succeed")
	assert.Equal(t, value, result, "Retrieved value should match")

	// Clean up
	err = rdb.Del(ctx, key)
	assert.NoError(t, err, "Del should succeed")
}

// TestRedisSetNX tests SetNX (set if not exists)
func TestRedisSetNX(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := RedisConfig{
		Host: "localhost",
		Port: 6379,
		DB:   0,
	}

	rdb, err := NewRedis(cfg)
	require.NoError(t, err)
	defer rdb.Close()

	ctx := context.Background()
	key := "test:setnx:1"

	// First SetNX should succeed
	ok, err := rdb.SetNX(ctx, key, "value1", 10*time.Second)
	assert.NoError(t, err)
	assert.True(t, ok, "First SetNX should succeed")

	// Second SetNX should fail (key exists)
	ok, err = rdb.SetNX(ctx, key, "value2", 10*time.Second)
	assert.NoError(t, err)
	assert.False(t, ok, "Second SetNX should fail")

	// Verify value is still the first one
	result, err := rdb.Get(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, "value1", result)

	// Clean up
	err = rdb.Del(ctx, key)
	assert.NoError(t, err)
}

// TestRedisIncr tests Incr and IncrBy operations
func TestRedisIncr(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := RedisConfig{
		Host: "localhost",
		Port: 6379,
		DB:   0,
	}

	rdb, err := NewRedis(cfg)
	require.NoError(t, err)
	defer rdb.Close()

	ctx := context.Background()
	key := "test:counter:1"

	// Incr by 1
	count, err := rdb.Incr(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Incr by 5
	count, err = rdb.IncrBy(ctx, key, 5)
	assert.NoError(t, err)
	assert.Equal(t, int64(6), count)

	// Clean up
	err = rdb.Del(ctx, key)
	assert.NoError(t, err)
}

// TestRedisExpire tests Expire and TTL operations
func TestRedisExpire(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := RedisConfig{
		Host: "localhost",
		Port: 6379,
		DB:   0,
	}

	rdb, err := NewRedis(cfg)
	require.NoError(t, err)
	defer rdb.Close()

	ctx := context.Background()
	key := "test:expire:1"

	// Set a value with no expiration
	err = rdb.Set(ctx, key, "value", 0)
	assert.NoError(t, err)

	// Set expiration
	err = rdb.Expire(ctx, key, 10*time.Second)
	assert.NoError(t, err)

	// Check TTL
	ttl, err := rdb.TTL(ctx, key)
	assert.NoError(t, err)
	assert.Greater(t, ttl, 0*time.Second, "TTL should be positive")
	assert.LessOrEqual(t, ttl, 10*time.Second, "TTL should not exceed set value")

	// Clean up
	err = rdb.Del(ctx, key)
	assert.NoError(t, err)
}

// TestRedisSet tests Set operations (SAdd, SMembers, SRem)
func TestRedisSet(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := RedisConfig{
		Host: "localhost",
		Port: 6379,
		DB:   0,
	}

	rdb, err := NewRedis(cfg)
	require.NoError(t, err)
	defer rdb.Close()

	ctx := context.Background()
	key := "test:set:1"

	// Add members to set
	err = rdb.SAdd(ctx, key, "member1", "member2", "member3")
	assert.NoError(t, err)

	// Get all members
	members, err := rdb.SMembers(ctx, key)
	assert.NoError(t, err)
	assert.Len(t, members, 3)
	assert.Contains(t, members, "member1")
	assert.Contains(t, members, "member2")
	assert.Contains(t, members, "member3")

	// Remove a member
	err = rdb.SRem(ctx, key, "member2")
	assert.NoError(t, err)

	// Verify member removed
	members, err = rdb.SMembers(ctx, key)
	assert.NoError(t, err)
	assert.Len(t, members, 2)
	assert.NotContains(t, members, "member2")

	// Clean up
	err = rdb.Del(ctx, key)
	assert.NoError(t, err)
}

// TestRedisExists tests Exists operation
func TestRedisExists(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := RedisConfig{
		Host: "localhost",
		Port: 6379,
		DB:   0,
	}

	rdb, err := NewRedis(cfg)
	require.NoError(t, err)
	defer rdb.Close()

	ctx := context.Background()
	key := "test:exists:1"

	// Key should not exist initially
	exists, err := rdb.Exists(ctx, key)
	assert.NoError(t, err)
	assert.False(t, exists)

	// Set the key
	err = rdb.Set(ctx, key, "value", 0)
	assert.NoError(t, err)

	// Key should exist now
	exists, err = rdb.Exists(ctx, key)
	assert.NoError(t, err)
	assert.True(t, exists)

	// Clean up
	err = rdb.Del(ctx, key)
	assert.NoError(t, err)
}

// TestRedisClose tests closing the connection
func TestRedisClose(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := RedisConfig{
		Host: "localhost",
		Port: 6379,
		DB:   0,
	}

	rdb, err := NewRedis(cfg)
	require.NoError(t, err)

	// Close the connection
	err = rdb.Close()
	assert.NoError(t, err, "Close should not error")

	// Ping should fail after close
	ctx := context.Background()
	err = rdb.Ping(ctx)
	assert.Error(t, err, "Ping should fail after close")
}

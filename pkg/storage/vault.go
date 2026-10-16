package storage

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	ErrQuotaExceeded = errors.New("vault quota exceeded")
	ErrNotFound      = errors.New("item not found in vault")
)

// TierRCache is an in-memory LRU cache representing Tier R (RAM cache) for 0.4s instant virtual mapping.
type TierRCache struct {
	mu         sync.RWMutex
	maxBytes   int64
	usedBytes  int64
	items      map[string]*list.Element
	evictQueue *list.List
}

type ramCacheItem struct {
	key   string
	value []byte
}

// NewTierRCache initializes Tier R in-memory segment cache.
func NewTierRCache(maxBytes int64) *TierRCache {
	if maxBytes <= 0 {
		maxBytes = 512 * 1024 * 1024 // 512 MiB default RAM cache
	}
	return &TierRCache{
		maxBytes:   maxBytes,
		items:      make(map[string]*list.Element),
		evictQueue: list.New(),
	}
}

// Get fetches data from RAM cache.
func (c *TierRCache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, found := c.items[key]
	if !found {
		return nil, false
	}
	c.evictQueue.MoveToFront(elem)
	item := elem.Value.(*ramCacheItem)
	return item.value, true
}

// Put adds data into RAM cache, evicting oldest if maxBytes exceeded.
func (c *TierRCache) Put(key string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	size := int64(len(data))
	// Oversized items cannot fit in cache: evict existing if present and decline to cache
	if size > c.maxBytes {
		if elem, found := c.items[key]; found {
			oldItem := elem.Value.(*ramCacheItem)
			c.usedBytes -= int64(len(oldItem.value))
			delete(c.items, key)
			c.evictQueue.Remove(elem)
		}
		return
	}

	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	if elem, found := c.items[key]; found {
		oldItem := elem.Value.(*ramCacheItem)
		c.usedBytes -= int64(len(oldItem.value))
		oldItem.value = dataCopy
		c.usedBytes += size
		c.evictQueue.MoveToFront(elem)
		for c.usedBytes > c.maxBytes && c.evictQueue.Len() > 1 {
			oldest := c.evictQueue.Back()
			if oldest != nil && oldest != elem {
				oldItem := oldest.Value.(*ramCacheItem)
				delete(c.items, oldItem.key)
				c.evictQueue.Remove(oldest)
				c.usedBytes -= int64(len(oldItem.value))
			} else {
				break
			}
		}
		return
	}

	for c.usedBytes+size > c.maxBytes && c.evictQueue.Len() > 0 {
		oldest := c.evictQueue.Back()
		if oldest != nil {
			oldItem := oldest.Value.(*ramCacheItem)
			delete(c.items, oldItem.key)
			c.evictQueue.Remove(oldest)
			c.usedBytes -= int64(len(oldItem.value))
		}
	}

	elem := c.evictQueue.PushFront(&ramCacheItem{key: key, value: dataCopy})
	c.items[key] = elem
	c.usedBytes += size
}

// Delete removes an entry from TierRCache.
func (c *TierRCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, found := c.items[key]; found {
		oldItem := elem.Value.(*ramCacheItem)
		c.usedBytes -= int64(len(oldItem.value))
		delete(c.items, key)
		c.evictQueue.Remove(elem)
	}
}

// Has checks if a key exists in Tier R.
func (c *TierRCache) Has(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, found := c.items[key]
	return found
}

// Vault manages Tier L (Local NVMe/SSD cache) on disk and coordinates with Tier R (RAM cache).
type Vault struct {
	mu         sync.RWMutex
	baseDir    string
	quotaBytes int64
	usedBytes  int64
	tierR      *TierRCache
	shards     map[string]string // shardKey -> filePath
	segments   map[string]string // segmentID -> filePath
}

// NewVault creates or opens a local storage vault at baseDir.
func NewVault(baseDir string, quotaBytes int64, ramCacheBytes int64) (*Vault, error) {
	if err := os.MkdirAll(filepath.Join(baseDir, "shards"), 0755); err != nil {
		return nil, fmt.Errorf("failed to create shards dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "segments"), 0755); err != nil {
		return nil, fmt.Errorf("failed to create segments dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "staging"), 0755); err != nil {
		return nil, fmt.Errorf("failed to create staging dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "chunks"), 0755); err != nil {
		return nil, fmt.Errorf("failed to create chunks dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "outputs"), 0755); err != nil {
		return nil, fmt.Errorf("failed to create outputs dir: %w", err)
	}

	v := &Vault{
		baseDir:    baseDir,
		quotaBytes: quotaBytes,
		tierR:      NewTierRCache(ramCacheBytes),
		shards:     make(map[string]string),
		segments:   make(map[string]string),
	}

	if err := v.scanExisting(); err != nil {
		return nil, err
	}

	return v, nil
}

func (v *Vault) scanExisting() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	var totalUsed int64

	// Scan shards
	shardFiles, _ := filepath.Glob(filepath.Join(v.baseDir, "shards", "*.shard"))
	for _, f := range shardFiles {
		fi, err := os.Stat(f)
		if err == nil {
			base := filepath.Base(f)
			v.shards[base] = f
			totalUsed += fi.Size()
		}
	}

	// Scan segments
	segFiles, _ := filepath.Glob(filepath.Join(v.baseDir, "segments", "*.seg"))
	for _, f := range segFiles {
		fi, err := os.Stat(f)
		if err == nil {
			base := filepath.Base(f)
			v.segments[base] = f
			totalUsed += fi.Size()
		}
	}

	// Scan chunks
	chunkFiles, _ := filepath.Glob(filepath.Join(v.baseDir, "chunks", "*.chunk"))
	for _, f := range chunkFiles {
		if fi, err := os.Stat(f); err == nil {
			totalUsed += fi.Size()
		}
	}

	// Scan outputs
	_ = filepath.Walk(filepath.Join(v.baseDir, "outputs"), func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			totalUsed += info.Size()
		}
		return nil
	})

	v.usedBytes = totalUsed
	return nil
}

// SetQuota adjusts the storage quota (e.g. from desktop slider).
func (v *Vault) SetQuota(bytes int64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.quotaBytes = bytes
}

// GetStats returns current capacity and usage.
func (v *Vault) GetStats() (usedBytes int64, quotaBytes int64, shardCount int, segmentCount int) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.usedBytes, v.quotaBytes, len(v.shards), len(v.segments)
}

// StoreShard writes a 2 MiB RS shard to Tier L disk storage.
func (v *Vault) StoreShard(segmentID string, shardIndex int, data []byte) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	shardKey := fmt.Sprintf("%s_%d.shard", segmentID, shardIndex)
	path := filepath.Join(v.baseDir, "shards", shardKey)

	var oldSize int64
	if _, exists := v.shards[shardKey]; exists {
		if fi, err := os.Stat(path); err == nil {
			oldSize = fi.Size()
		}
	}

	size := int64(len(data))
	if v.quotaBytes > 0 && (v.usedBytes-oldSize)+size > v.quotaBytes {
		return "", ErrQuotaExceeded
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write shard: %w", err)
	}

	v.shards[shardKey] = path
	v.usedBytes = (v.usedBytes - oldSize) + size

	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// ReadShard loads a shard from Tier L.
func (v *Vault) ReadShard(segmentID string, shardIndex int) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	shardKey := fmt.Sprintf("%s_%d.shard", segmentID, shardIndex)
	path, ok := v.shards[shardKey]
	if !ok {
		return nil, ErrNotFound
	}

	return os.ReadFile(path)
}

// StoreSegment stores a full 64 MiB segment in Tier L and caches in Tier R.
func (v *Vault) StoreSegment(segmentID string, data []byte) error {
	v.mu.Lock()
	segKey := fmt.Sprintf("%s.seg", segmentID)
	path := filepath.Join(v.baseDir, "segments", segKey)

	var oldSize int64
	if _, exists := v.segments[segKey]; exists {
		if fi, err := os.Stat(path); err == nil {
			oldSize = fi.Size()
		}
	}

	size := int64(len(data))
	if v.quotaBytes > 0 && (v.usedBytes-oldSize)+size > v.quotaBytes {
		v.mu.Unlock()
		return ErrQuotaExceeded
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		v.mu.Unlock()
		return fmt.Errorf("failed to write segment: %w", err)
	}

	v.segments[segKey] = path
	v.usedBytes = (v.usedBytes - oldSize) + size
	v.mu.Unlock()

	// Put in Tier R memory cache
	v.tierR.Put(segmentID, data)
	return nil
}

// ReadSegment reads a full segment, checking Tier R (RAM) first, then falling back to Tier L (Disk).
func (v *Vault) ReadSegment(segmentID string) ([]byte, string, error) {
	// 1. Check Tier R (RAM cache) - 0.4s fast path
	if data, ok := v.tierR.Get(segmentID); ok {
		return data, "Tier_R", nil
	}

	// 2. Check Tier L (NVMe/Disk cache) - 13.6s path
	v.mu.RLock()
	segKey := fmt.Sprintf("%s.seg", segmentID)
	path, ok := v.segments[segKey]
	v.mu.RUnlock()

	if !ok {
		return nil, "Cold", ErrNotFound
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "Cold", err
	}

	// Promote to Tier R
	v.tierR.Put(segmentID, data)
	return data, "Tier_L", nil
}

// HasSegmentLocality checks whether the segment is in Tier R, Tier L, or absent.
func (v *Vault) HasSegmentLocality(segmentID string) string {
	if v.tierR.Has(segmentID) {
		return "Tier_R"
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	segKey := fmt.Sprintf("%s.seg", segmentID)
	if _, ok := v.segments[segKey]; ok {
		return "Tier_L"
	}
	return "Cold"
}

// ListStoredShards returns a list of all stored shard keys.
func (v *Vault) ListStoredShards() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	res := make([]string, 0, len(v.shards))
	for k := range v.shards {
		res = append(res, k)
	}
	return res
}

// DeleteShard removes a stored shard from disk and updates quota accounting.
func (v *Vault) DeleteShard(segmentID string, shardIndex int) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	shardKey := fmt.Sprintf("%s_%d.shard", segmentID, shardIndex)
	path, ok := v.shards[shardKey]
	if !ok {
		return ErrNotFound
	}

	if fi, err := os.Stat(path); err == nil {
		v.usedBytes -= fi.Size()
	}
	delete(v.shards, shardKey)
	return os.Remove(path)
}

// DeleteSegment removes a stored segment from disk and Tier R cache.
func (v *Vault) DeleteSegment(segmentID string) error {
	v.mu.Lock()
	segKey := fmt.Sprintf("%s.seg", segmentID)
	path, ok := v.segments[segKey]
	if !ok {
		v.mu.Unlock()
		return ErrNotFound
	}

	if fi, err := os.Stat(path); err == nil {
		v.usedBytes -= fi.Size()
	}
	delete(v.segments, segKey)
	v.mu.Unlock()

	v.tierR.Delete(segmentID)
	return os.Remove(path)
}

// StoreChunk stores a content-addressed chunk or file payload into the vault (Tier L and Tier R).
func (v *Vault) StoreChunk(cid string, data []byte) error {
	v.mu.Lock()
	chunkPath := filepath.Join(v.baseDir, "chunks", cid+".chunk")
	var oldSize int64
	if fi, err := os.Stat(chunkPath); err == nil {
		oldSize = fi.Size()
	}

	size := int64(len(data))
	if v.quotaBytes > 0 && (v.usedBytes-oldSize)+size > v.quotaBytes {
		v.mu.Unlock()
		return ErrQuotaExceeded
	}

	if err := os.WriteFile(chunkPath, data, 0644); err != nil {
		v.mu.Unlock()
		return fmt.Errorf("failed to write chunk: %w", err)
	}

	v.usedBytes = (v.usedBytes - oldSize) + size
	v.mu.Unlock()

	v.tierR.Put(cid, data)
	return nil
}

// ReadChunk retrieves a content-addressed chunk or file from the vault.
func (v *Vault) ReadChunk(cid string) ([]byte, error) {
	if data, ok := v.tierR.Get(cid); ok {
		return data, nil
	}

	v.mu.RLock()
	chunkPath := filepath.Join(v.baseDir, "chunks", cid+".chunk")
	v.mu.RUnlock()

	data, err := os.ReadFile(chunkPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	v.tierR.Put(cid, data)
	return data, nil
}

// StoreOutput stores an executed task output file into the vault under outputs/<taskID>/<filename>.
func (v *Vault) StoreOutput(taskID, filename string, data []byte) (string, error) {
	v.mu.Lock()
	taskOutputDir := filepath.Join(v.baseDir, "outputs", taskID)
	if err := os.MkdirAll(taskOutputDir, 0755); err != nil {
		v.mu.Unlock()
		return "", fmt.Errorf("failed to create task output dir: %w", err)
	}

	cleanFilename := filepath.Clean(filename)
	if filepath.IsAbs(cleanFilename) || strings.HasPrefix(cleanFilename, "..") {
		cleanFilename = filepath.Base(cleanFilename)
	}
	outPath := filepath.Join(taskOutputDir, cleanFilename)
	_ = os.MkdirAll(filepath.Dir(outPath), 0755)

	var oldSize int64
	if fi, err := os.Stat(outPath); err == nil {
		oldSize = fi.Size()
	}

	size := int64(len(data))
	if v.quotaBytes > 0 && (v.usedBytes-oldSize)+size > v.quotaBytes {
		v.mu.Unlock()
		return "", ErrQuotaExceeded
	}

	if err := os.WriteFile(outPath, data, 0644); err != nil {
		v.mu.Unlock()
		return "", fmt.Errorf("failed to write output file: %w", err)
	}

	v.usedBytes = (v.usedBytes - oldSize) + size
	v.mu.Unlock()

	h := sha256.Sum256(data)
	cid := hex.EncodeToString(h[:])
	_ = v.StoreChunk(cid, data)

	return cid, nil
}

// ReadOutput retrieves an executed task output file from the vault.
func (v *Vault) ReadOutput(taskID, filename string) ([]byte, error) {
	cleanFilename := filepath.Clean(filename)
	if filepath.IsAbs(cleanFilename) || strings.HasPrefix(cleanFilename, "..") {
		cleanFilename = filepath.Base(cleanFilename)
	}

	v.mu.RLock()
	outPath := filepath.Join(v.baseDir, "outputs", taskID, cleanFilename)
	v.mu.RUnlock()

	data, err := os.ReadFile(outPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return data, nil
}

// ListOutputs lists all output filenames for a given task ID.
func (v *Vault) ListOutputs(taskID string) ([]string, error) {
	v.mu.RLock()
	taskOutputDir := filepath.Join(v.baseDir, "outputs", taskID)
	v.mu.RUnlock()

	var files []string
	err := filepath.Walk(taskOutputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, errRel := filepath.Rel(taskOutputDir, path)
		if errRel == nil {
			files = append(files, rel)
		}
		return nil
	})
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	return files, err
}

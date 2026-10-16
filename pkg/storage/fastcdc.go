package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// FastCDC parameters according to Section 4 & 9 (8 KiB min, 16 KiB avg, 64 KiB max).
const (
	DefaultMinChunkSize = 8 * 1024  // 8 KiB
	DefaultAvgChunkSize = 16 * 1024 // 16 KiB
	DefaultMaxChunkSize = 64 * 1024 // 64 KiB

	// Masks for 16 KiB average chunk size (2^14 bytes).
	// Normal mask has 15 ones, small mask has 13 ones.
	maskS = 0x0000dfff // 13 bits set
	maskL = 0x00007fff // 15 bits set
)

// Gear table for 64-bit FastCDC rolling hash.
var gearTable = [256]uint32{
	0x00000000, 0x01020408, 0x02040810, 0x03060c18, 0x04081020, 0x050a1428, 0x060c1830, 0x070e1c38,
	0x08102040, 0x09122448, 0x0a142850, 0x0b162c58, 0x0c183060, 0x0d1a3468, 0x0e1c3870, 0x0f1e3c78,
	0x10204080, 0x11224488, 0x12244890, 0x13264c98, 0x142850a0, 0x152a54a8, 0x162c58b0, 0x172e5cb8,
	0x183060c0, 0x193264c8, 0x1a3468d0, 0x1b366cd8, 0x1c3870e0, 0x1d3a74e8, 0x1e3c78f0, 0x1f3e7cf8,
	0x20408100, 0x21428508, 0x22448910, 0x23468d18, 0x24489120, 0x254a9528, 0x264c9930, 0x274e9d38,
	0x2850a140, 0x2952a548, 0x2a54a950, 0x2b56ad58, 0x2c58b160, 0x2d5ab568, 0x2e5cb970, 0x2f5ebd78,
	0x3060c180, 0x3162c588, 0x3264c990, 0x3366cd98, 0x3468d1a0, 0x356ad5a8, 0x366cd9b0, 0x376eddb8,
	0x3870e1c0, 0x3972e5c8, 0x3a74e9d0, 0x3b76edd8, 0x3c78f1e0, 0x3d7af5e8, 0x3e7cf9f0, 0x3f7efdf8,
	0x40810200, 0x41830608, 0x42850a10, 0x43870e18, 0x44891220, 0x458b1628, 0x468d1a30, 0x478f1e38,
	0x48912240, 0x49932648, 0x4a952a50, 0x4b972e58, 0x4c993260, 0x4d9b3668, 0x4e9d3a70, 0x4f9f3e78,
	0x50a14280, 0x51a34688, 0x52a54a90, 0x53a74e98, 0x54a952a0, 0x55ab56a8, 0x56ad5ab0, 0x57af5eb8,
	0x58b162c0, 0x59b366c8, 0x5ab56ad0, 0x5bb76ed8, 0x5cb972e0, 0x5dbb76e8, 0x5ebf7bb0, 0x5fbf7ef8,
	0x60c18300, 0x61c38708, 0x62c58b10, 0x63c78f18, 0x64c99320, 0x65cb9728, 0x66cd9b30, 0x67cf9f38,
	0x68d1a340, 0x69d3a748, 0x6ad5ab50, 0x6bd7af58, 0x6cd9b360, 0x6cdbb768, 0x6eddbb70, 0x6fedbf78,
	0x70e1c380, 0x71e3c788, 0x72e5cb90, 0x73e7cf98, 0x74e9d3a0, 0x75ebd7a8, 0x76eddbb0, 0x77efdfb8,
	0x78f1e3c0, 0x79f3e7c8, 0x7af5ebb0, 0x7bf7efb8, 0x7cf9f3e0, 0x7dfbf7e8, 0x7efdfbf0, 0x7ffffffe,
	0x81020400, 0x82040801, 0x83060c02, 0x84081003, 0x850a1404, 0x860c1805, 0x870e1c06, 0x88102007,
	0x89122408, 0x8a142809, 0x8b162c0a, 0x8c18300b, 0x8d1a340c, 0x8e1c380d, 0x8f1e3c0e, 0x9020400f,
	0x91224410, 0x92244811, 0x93264c12, 0x94285013, 0x952a5414, 0x962c5815, 0x972e5c16, 0x98306017,
	0x99326418, 0x9a346819, 0x9b366c1a, 0x9c38701b, 0x9d3a741c, 0x9e3c781d, 0x9f3e7c1e, 0xa040801f,
	0xa1428420, 0xa2448821, 0xa3468c22, 0xa4489023, 0xa54a9424, 0xa64c9825, 0xa74e9c26, 0xa850a027,
	0xa952a428, 0xaa54a829, 0xab56ac2a, 0xac58b02b, 0xad5ab42c, 0xae5cb82d, 0xaf5ebc2e, 0xb060c02f,
	0xb162c430, 0xb264c831, 0xb366cc32, 0xb468d033, 0xb56ad434, 0xb66cd835, 0xb76edc36, 0xb870e037,
	0xb972e438, 0xba74e839, 0xbb76ec3a, 0xbc78f03b, 0xbd7af43c, 0xbe7cf83d, 0xbf7efc3e, 0xc080003f,
	0xc1820440, 0xc2840841, 0xc3860c42, 0xc4881043, 0xc58a1444, 0xc68c1845, 0xc78e1c46, 0xc8902047,
	0xc9922448, 0xca942849, 0xcb962c4a, 0xcc98304b, 0xcd9a344c, 0xce9c384d, 0xcf9e3c4e, 0xd0a0404f,
	0xd1a24450, 0xd2a44851, 0xd3a64c52, 0xd4a85053, 0xd5aa5454, 0xd6ac5855, 0xd7ae5c56, 0xd8b06057,
	0xd9b26458, 0xdab46859, 0xdbb66c5a, 0xdcb8705b, 0xddba745c, 0xdebc785d, 0xdfbe7c5e, 0xe0c0805f,
	0xe1c28460, 0xe2c48861, 0xe3c68c62, 0xe4c89063, 0xe5ca9464, 0xe6cc9865, 0xe7ce9c66, 0xe8d0a067,
	0xe9d2a468, 0xead4a869, 0xebd6ac6a, 0xecd8b06b, 0xedda746c, 0xeedc786d, 0xefde7c6e, 0xf0e0806f,
	0xf1e28470, 0xf2e48871, 0xf3e68c72, 0xf4e89073, 0xf5ea9474, 0xf6ec9875, 0xf7ee9c76, 0xf8f0a077,
	0xf9f2a478, 0xfaf4a879, 0xfbf6ac7a, 0xfcf8b07b, 0xfdfa747c, 0xfefc787d, 0xfffe7c7e, 0xffffffff,
}

// Chunk represents a single variable-length block produced by FastCDC.
type Chunk struct {
	Data         []byte
	Offset       int64
	Length       int64
	PlaintextCID string
}

// FastCDC implements gear-based normalized content-defined chunking.
type FastCDC struct {
	minSize int
	avgSize int
	maxSize int
}

// NewFastCDC creates a new FastCDC chunker with default 8K/16K/64K boundaries.
func NewFastCDC() *FastCDC {
	return &FastCDC{
		minSize: DefaultMinChunkSize,
		avgSize: DefaultAvgChunkSize,
		maxSize: DefaultMaxChunkSize,
	}
}

// NewFastCDCCustom creates a FastCDC chunker with custom min, avg, max sizes.
func NewFastCDCCustom(minSize, avgSize, maxSize int) *FastCDC {
	if minSize <= 0 {
		minSize = DefaultMinChunkSize
	}
	if avgSize <= minSize {
		avgSize = minSize * 2
	}
	if maxSize <= avgSize {
		maxSize = avgSize * 4
	}
	return &FastCDC{
		minSize: minSize,
		avgSize: avgSize,
		maxSize: maxSize,
	}
}

// ChunkBytes slices a byte slice into variable-length FastCDC chunks.
func (cdc *FastCDC) ChunkBytes(data []byte) []Chunk {
	var chunks []Chunk
	n := len(data)
	if n == 0 {
		return chunks
	}

	offset := 0
	for offset < n {
		remaining := n - offset
		if remaining <= cdc.minSize {
			chunkData := data[offset:]
			cid := sha256.Sum256(chunkData)
			chunks = append(chunks, Chunk{
				Data:         chunkData,
				Offset:       int64(offset),
				Length:       int64(len(chunkData)),
				PlaintextCID: hex.EncodeToString(cid[:]),
			})
			break
		}

		// Minimum window: cannot cut before minSize
		cutPoint := cdc.findCutPoint(data[offset:])
		chunkLen := cutPoint
		if chunkLen <= 0 {
			chunkLen = cdc.minSize
			if chunkLen > remaining {
				chunkLen = remaining
			}
		}
		chunkData := data[offset : offset+chunkLen]
		cid := sha256.Sum256(chunkData)

		chunks = append(chunks, Chunk{
			Data:         chunkData,
			Offset:       int64(offset),
			Length:       int64(chunkLen),
			PlaintextCID: hex.EncodeToString(cid[:]),
		})

		offset += chunkLen
	}

	return chunks
}

// ChunkReader reads from an io.Reader and slices into FastCDC chunks.
func (cdc *FastCDC) ChunkReader(r io.Reader) ([]Chunk, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return cdc.ChunkBytes(data), nil
}

// findCutPoint determines the boundary for the current chunk.
func (cdc *FastCDC) findCutPoint(data []byte) int {
	n := len(data)
	if n <= cdc.minSize {
		return n
	}

	maxPossible := cdc.maxSize
	if n < maxPossible {
		maxPossible = n
	}

	var fp uint32 = 0
	i := cdc.minSize

	// Phase 1: from minSize up to avgSize, test using maskS
	phase1End := cdc.avgSize
	if phase1End > maxPossible {
		phase1End = maxPossible
	}

	for ; i < phase1End; i++ {
		b := data[i]
		fp = (fp << 1) + gearTable[b]
		if (fp & maskS) == 0 {
			return i + 1
		}
	}

	// Phase 2: from avgSize up to maxSize, test using maskL
	for ; i < maxPossible; i++ {
		b := data[i]
		fp = (fp << 1) + gearTable[b]
		if (fp & maskL) == 0 {
			return i + 1
		}
	}

	return maxPossible
}

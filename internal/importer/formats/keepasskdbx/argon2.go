// Argon2d / Argon2id with selectable version (0x10 and 0x13), adapted from golang.org/x/crypto/argon2
// (Copyright 2017 The Go Authors, BSD-style license), which only exposes Argon2i/Argon2id at
// version 0x13. KDBX 4 defaults to Argon2d, and the keepass crate also accepts version 0x10.

package keepasskdbx

import (
	"encoding/binary"
	"errors"
	"hash"
	"sync"

	"golang.org/x/crypto/blake2b"
)

const (
	argon2d  = 0
	argon2i  = 1 // only used by tests (reference vectors)
	argon2id = 2

	argon2Version10 = 0x10
	argon2Version13 = 0x13

	argon2BlockLength = 128
	argon2SyncPoints  = 4
)

type argon2Block [argon2BlockLength]uint64

// argon2Params mirrors argon2::Config as built by the keepass crate's Argon2Kdf.
type argon2Params struct {
	mode     int
	version  uint32
	time     uint32 // time_cost (iterations as u32)
	memory   uint32 // mem_cost in KiB ((memory / 1024) as u32)
	lanes    uint32 // parallelism
	salt     []byte
	password []byte
}

var errArgon2Params = errors.New("argon2: invalid parameters")

// maxArgon2MemoryKiB caps the memory a (possibly hostile) file can make us allocate. The Rust
// crate has no such limit (it would try to allocate up to 4 TiB).
const maxArgon2MemoryKiB = 4 * 1024 * 1024

// argon2Key validates the parameters like rust-argon2's Context::new and derives a 32-byte key.
func argon2Key(p argon2Params) ([]byte, error) {
	if p.lanes < 1 || p.lanes > 0xFFFFFF {
		return nil, errArgon2Params
	}
	if p.time < 1 {
		return nil, errArgon2Params
	}
	if uint64(p.memory) < 8*uint64(p.lanes) {
		return nil, errArgon2Params
	}
	if len(p.salt) < 8 {
		return nil, errArgon2Params
	}
	if p.memory > maxArgon2MemoryKiB {
		return nil, errArgon2TooLarge
	}
	const keyLen = 32
	h0 := argon2InitHash(p, keyLen)

	memory := p.memory / (argon2SyncPoints * p.lanes) * (argon2SyncPoints * p.lanes)
	if memory < 2*argon2SyncPoints*p.lanes {
		memory = 2 * argon2SyncPoints * p.lanes
	}
	B := argon2InitBlocks(&h0, memory, p.lanes)
	argon2ProcessBlocks(B, p.time, memory, p.lanes, p.mode, p.version)
	return argon2ExtractKey(B, memory, p.lanes, keyLen), nil
}

var errArgon2TooLarge = errors.New("argon2: memory cost too large")

func argon2InitHash(p argon2Params, keyLen uint32) [blake2b.Size + 8]byte {
	var (
		h0     [blake2b.Size + 8]byte
		params [24]byte
		tmp    [4]byte
	)
	b2, _ := blake2b.New512(nil)
	binary.LittleEndian.PutUint32(params[0:4], p.lanes)
	binary.LittleEndian.PutUint32(params[4:8], keyLen)
	binary.LittleEndian.PutUint32(params[8:12], p.memory)
	binary.LittleEndian.PutUint32(params[12:16], p.time)
	binary.LittleEndian.PutUint32(params[16:20], p.version)
	binary.LittleEndian.PutUint32(params[20:24], uint32(p.mode))
	b2.Write(params[:])
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(p.password)))
	b2.Write(tmp[:])
	b2.Write(p.password)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(p.salt)))
	b2.Write(tmp[:])
	b2.Write(p.salt)
	binary.LittleEndian.PutUint32(tmp[:], 0) // secret
	b2.Write(tmp[:])
	binary.LittleEndian.PutUint32(tmp[:], 0) // associated data
	b2.Write(tmp[:])
	b2.Sum(h0[:0])
	return h0
}

func argon2InitBlocks(h0 *[blake2b.Size + 8]byte, memory, lanes uint32) []argon2Block {
	var block0 [1024]byte
	B := make([]argon2Block, memory)
	for lane := uint32(0); lane < lanes; lane++ {
		j := lane * (memory / lanes)
		binary.LittleEndian.PutUint32(h0[blake2b.Size+4:], lane)

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 0)
		argon2Blake2bHash(block0[:], h0[:])
		for i := range B[j+0] {
			B[j+0][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 1)
		argon2Blake2bHash(block0[:], h0[:])
		for i := range B[j+1] {
			B[j+1][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}
	}
	return B
}

func argon2ProcessBlocks(B []argon2Block, time, memory, lanesCount uint32, mode int, version uint32) {
	lanes := memory / lanesCount
	segments := lanes / argon2SyncPoints

	processSegment := func(n, slice, lane uint32, wg *sync.WaitGroup) {
		defer wg.Done()
		var addresses, in, zero argon2Block
		dataIndependent := mode == argon2i || mode == argon2id && n == 0 && slice < argon2SyncPoints/2
		if dataIndependent {
			in[0] = uint64(n)
			in[1] = uint64(lane)
			in[2] = uint64(slice)
			in[3] = uint64(memory)
			in[4] = uint64(time)
			in[5] = uint64(mode)
		}

		index := uint32(0)
		if n == 0 && slice == 0 {
			index = 2 // the first two blocks are already generated
			if dataIndependent {
				in[6]++
				argon2ProcessBlock(&addresses, &in, &zero, false)
				argon2ProcessBlock(&addresses, &addresses, &zero, false)
			}
		}

		offset := lane*lanes + slice*segments + index
		var random uint64
		for index < segments {
			prev := offset - 1
			if index == 0 && slice == 0 {
				prev += lanes // last block in lane
			}
			if dataIndependent {
				if index%argon2BlockLength == 0 {
					in[6]++
					argon2ProcessBlock(&addresses, &in, &zero, false)
					argon2ProcessBlock(&addresses, &addresses, &zero, false)
				}
				random = addresses[index%argon2BlockLength]
			} else {
				random = B[prev][0]
			}
			newOffset := argon2IndexAlpha(random, lanes, segments, lanesCount, n, slice, lane, index)
			// Version 0x10 overwrites blocks on every pass; 0x13 XORs from the second pass on (on the
			// first pass the destination is still zero, so XOR equals overwrite).
			argon2ProcessBlock(&B[offset], &B[prev], &B[newOffset], version != argon2Version10)
			index, offset = index+1, offset+1
		}
	}

	for n := uint32(0); n < time; n++ {
		for slice := uint32(0); slice < argon2SyncPoints; slice++ {
			var wg sync.WaitGroup
			for lane := uint32(0); lane < lanesCount; lane++ {
				wg.Add(1)
				go processSegment(n, slice, lane, &wg)
			}
			wg.Wait()
		}
	}
}

func argon2ExtractKey(B []argon2Block, memory, lanesCount, keyLen uint32) []byte {
	lanes := memory / lanesCount
	for lane := uint32(0); lane < lanesCount-1; lane++ {
		for i, v := range B[(lane*lanes)+lanes-1] {
			B[memory-1][i] ^= v
		}
	}
	var block [1024]byte
	for i, v := range B[memory-1] {
		binary.LittleEndian.PutUint64(block[i*8:], v)
	}
	key := make([]byte, keyLen)
	argon2Blake2bHash(key, block[:])
	return key
}

func argon2IndexAlpha(rand uint64, lanes, segments, threads, n, slice, lane, index uint32) uint32 {
	refLane := uint32(rand>>32) % threads
	if n == 0 && slice == 0 {
		refLane = lane
	}
	m, s := 3*segments, ((slice+1)%argon2SyncPoints)*segments
	if lane == refLane {
		m += index
	}
	if n == 0 {
		m, s = slice*segments, 0
		if slice == 0 || lane == refLane {
			m += index
		}
	}
	if index == 0 || lane == refLane {
		m--
	}
	p := rand & 0xFFFFFFFF
	p = (p * p) >> 32
	p = (p * uint64(m)) >> 32
	return refLane*lanes + uint32((uint64(s)+uint64(m)-(p+1))%uint64(lanes))
}

// argon2Blake2bHash is Argon2's variable-length hash H'.
func argon2Blake2bHash(out []byte, in []byte) {
	var b2 hash.Hash
	if n := len(out); n < blake2b.Size {
		b2, _ = blake2b.New(n, nil)
	} else {
		b2, _ = blake2b.New512(nil)
	}
	var buffer [blake2b.Size]byte
	binary.LittleEndian.PutUint32(buffer[:4], uint32(len(out)))
	b2.Write(buffer[:4])
	b2.Write(in)
	if len(out) <= blake2b.Size {
		b2.Sum(out[:0])
		return
	}
	outLen := len(out)
	b2.Sum(buffer[:0])
	b2.Reset()
	copy(out, buffer[:32])
	out = out[32:]
	for len(out) > blake2b.Size {
		b2.Write(buffer[:])
		b2.Sum(buffer[:0])
		copy(out, buffer[:32])
		out = out[32:]
		b2.Reset()
	}
	if outLen%blake2b.Size > 0 {
		r := ((outLen + 31) / 32) - 2
		b2, _ = blake2b.New(outLen-32*r, nil)
	}
	b2.Write(buffer[:])
	b2.Sum(out[:0])
}

func argon2ProcessBlock(out, in1, in2 *argon2Block, xor bool) {
	var t argon2Block
	for i := range t {
		t[i] = in1[i] ^ in2[i]
	}
	for i := 0; i < argon2BlockLength; i += 16 {
		blamka(
			&t[i+0], &t[i+1], &t[i+2], &t[i+3],
			&t[i+4], &t[i+5], &t[i+6], &t[i+7],
			&t[i+8], &t[i+9], &t[i+10], &t[i+11],
			&t[i+12], &t[i+13], &t[i+14], &t[i+15],
		)
	}
	for i := 0; i < argon2BlockLength/8; i += 2 {
		blamka(
			&t[i], &t[i+1], &t[16+i], &t[16+i+1],
			&t[32+i], &t[32+i+1], &t[48+i], &t[48+i+1],
			&t[64+i], &t[64+i+1], &t[80+i], &t[80+i+1],
			&t[96+i], &t[96+i+1], &t[112+i], &t[112+i+1],
		)
	}
	if xor {
		for i := range t {
			out[i] ^= in1[i] ^ in2[i] ^ t[i]
		}
	} else {
		for i := range t {
			out[i] = in1[i] ^ in2[i] ^ t[i]
		}
	}
}

func fBlaMka(x, y uint64) uint64 { return x + y + 2*uint64(uint32(x))*uint64(uint32(y)) }

func rotr64(x uint64, n uint) uint64 { return x>>n | x<<(64-n) }

func gb(a, b, c, d *uint64) {
	*a = fBlaMka(*a, *b)
	*d = rotr64(*d^*a, 32)
	*c = fBlaMka(*c, *d)
	*b = rotr64(*b^*c, 24)
	*a = fBlaMka(*a, *b)
	*d = rotr64(*d^*a, 16)
	*c = fBlaMka(*c, *d)
	*b = rotr64(*b^*c, 63)
}

func blamka(t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t12, t13, t14, t15 *uint64) {
	gb(t00, t04, t08, t12)
	gb(t01, t05, t09, t13)
	gb(t02, t06, t10, t14)
	gb(t03, t07, t11, t15)
	gb(t00, t05, t10, t15)
	gb(t01, t06, t11, t12)
	gb(t02, t07, t08, t13)
	gb(t03, t04, t09, t14)
}

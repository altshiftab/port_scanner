// Package permutation provides a keyed bijection on [0, size), so that a scan can visit every
// target exactly once in a pseudo-random order without materialising the order.
//
// The construction is the one masscan uses: an unbalanced Feistel network over a domain of a×b ≥
// size elements, with cycle walking to fold the few values that land at or beyond size back into
// range. Because every step is a bijection, so is the whole, and Index(i) for i in [0, size) is a
// permutation of [0, size).
package permutation

import (
	"math"
)

const (
	// rounds is how many Feistel rounds are applied. Three suffice to decorrelate consecutive
	// indices; there is no cryptographic requirement here.
	rounds = 3
	// roundSalt separates the round functions from one another.
	roundSalt uint64 = 0x9E3779B97F4A7C15
)

// Permutation is a bijection on [0, Size).
type Permutation struct {
	size uint64
	a    uint64
	b    uint64
	seed uint64
}

// New returns the permutation of [0, size) selected by seed. The same seed and size always give the
// same permutation.
func New(size uint64, seed uint64) *Permutation {
	// a ≈ √size, b = ⌈size / a⌉, so that a×b ≥ size while staying as close to it as possible, which
	// keeps the expected number of cycle-walking steps below two.
	a := uint64(math.Sqrt(float64(size)))
	if a == 0 {
		a = 1
	}

	b := size / a
	if b*a < size {
		b++
	}

	return &Permutation{size: size, a: a, b: b, seed: seed}
}

// Size returns the number of elements the permutation ranges over.
func (permutation *Permutation) Size() uint64 {
	return permutation.size
}

// mix is the splitmix64 finaliser: a cheap, well-distributed 64-bit mixing function.
func mix(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 27
	x *= 0x94D049BB133111EB
	x ^= x >> 31
	return x
}

// round is the Feistel round function: any deterministic function of the round number and the
// right half keeps the network a bijection.
func (permutation *Permutation) round(j uint64, right uint64) uint64 {
	return mix(right ^ permutation.seed ^ (j * roundSalt))
}

// encrypt maps [0, a×b) onto itself.
func (permutation *Permutation) encrypt(m uint64) uint64 {
	a, b := permutation.a, permutation.b

	left, right := m%a, m/a
	for j := uint64(1); j <= rounds; j++ {
		// The modulus alternates with the parity of the round, following the shape of the halves:
		// on odd rounds the left half ranges over [0, a), on even rounds over [0, b). Reducing the
		// round function first keeps the sum from wrapping, which would break the bijection.
		modulus := a
		if j%2 == 0 {
			modulus = b
		}

		left, right = right, (left+permutation.round(j, right)%modulus)%modulus
	}

	if rounds%2 == 1 {
		return a*left + right
	}

	return a*right + left
}

// Index returns the element that position i of the permutation holds. It is a bijection on
// [0, Size()); i at or beyond Size() is folded into range like any other value and so may collide
// with a valid position.
func (permutation *Permutation) Index(i uint64) uint64 {
	if permutation.size == 0 {
		return 0
	}

	c := permutation.encrypt(i)
	for c >= permutation.size {
		c = permutation.encrypt(c)
	}

	return c
}

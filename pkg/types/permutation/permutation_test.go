package permutation

import (
	"testing"
)

func TestIndexIsPermutation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		size uint64
		seed uint64
	}{
		{name: "empty", size: 0, seed: 1},
		{name: "one", size: 1, seed: 1},
		{name: "two", size: 2, seed: 7},
		{name: "three", size: 3, seed: 3},
		{name: "prime", size: 7919, seed: 42},
		{name: "square", size: 4096, seed: 0},
		{name: "square plus one", size: 4097, seed: 99},
		{name: "square minus one", size: 4095, seed: 99},
		{name: "power of two", size: 65536, seed: 1234567},
		{name: "odd", size: 100001, seed: 0xDEADBEEF},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			permutation := New(testCase.size, testCase.seed)
			if got := permutation.Size(); got != testCase.size {
				t.Fatalf("Size() = %d, want %d", got, testCase.size)
			}

			seen := make([]bool, testCase.size)
			for i := range testCase.size {
				index := permutation.Index(i)
				if index >= testCase.size {
					t.Fatalf("Index(%d) = %d, outside [0, %d)", i, index, testCase.size)
				}
				if seen[index] {
					t.Fatalf("Index(%d) = %d, already produced", i, index)
				}
				seen[index] = true
			}
		})
	}
}

func TestIndexIsDeterministic(t *testing.T) {
	t.Parallel()

	const size = 1000

	first := New(size, 5)
	second := New(size, 5)
	other := New(size, 6)

	var differs bool
	for i := range uint64(size) {
		if first.Index(i) != second.Index(i) {
			t.Fatalf("Index(%d) differs between two permutations of the same seed", i)
		}
		if first.Index(i) != other.Index(i) {
			differs = true
		}
	}

	if !differs {
		t.Fatalf("permutations of different seeds are identical")
	}
}

func TestIndexShuffles(t *testing.T) {
	t.Parallel()

	// A permutation that leaves most elements in place would defeat the purpose. Count fixed
	// points; a random permutation has about one.
	const size = 10000

	permutation := New(size, 12345)

	var fixedPoints int
	for i := range uint64(size) {
		if permutation.Index(i) == i {
			fixedPoints++
		}
	}

	if fixedPoints > size/100 {
		t.Fatalf("%d fixed points out of %d; the permutation barely shuffles", fixedPoints, size)
	}
}

func TestNewChoosesCoveringFactors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		size uint64
	}{
		{name: "zero", size: 0},
		{name: "one", size: 1},
		{name: "two", size: 2},
		{name: "prime", size: 101},
		{name: "square", size: 144},
		{name: "large", size: 1 << 40},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			permutation := New(testCase.size, 0)
			if permutation.a == 0 {
				t.Fatalf("a = 0")
			}
			if permutation.a*permutation.b < testCase.size {
				t.Fatalf("a×b = %d×%d = %d < size %d", permutation.a, permutation.b, permutation.a*permutation.b, testCase.size)
			}
		})
	}
}

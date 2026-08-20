package merkletree_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"entiergo.org/merkletree"
	basic "entiergo.org/merkletree-basic"
)

type basicContent string

func (c basicContent) CalculateHash() ([]byte, error) {
	h := sha256.Sum256([]byte(c))
	return h[:], nil
}

func (c basicContent) Equals(other merkletree.Content) (bool, error) {
	o, ok := other.(basicContent)
	return ok && c == o, nil
}

func TestBasicRootsMatchDefault(t *testing.T) {
	for n := 1; n <= 17; n++ {
		leaves := make([][]byte, n)
		contents := make([]merkletree.Content, n)
		for i := range leaves {
			contents[i] = basicContent(string(rune('a' + i)))
			leaves[i], _ = contents[i].CalculateHash()
		}
		small, err := basic.NewTree(leaves)
		if err != nil {
			t.Fatal(err)
		}
		full, err := merkletree.NewTree(contents)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(small.MerkleRoot(), full.MerkleRoot()) {
			t.Fatalf("%d leaves: roots differ", n)
		}
		valid, err := full.VerifyTree()
		if err != nil || !valid {
			t.Fatalf("%d leaves: full tree does not verify: %v, %v", n, valid, err)
		}
		for i := range contents {
			path, sides, err := full.GetMerklePathByIndex(i)
			if err != nil {
				t.Fatal(err)
			}
			valid, err := merkletree.VerifyProof(contents[i], path, sides, full.MerkleRoot())
			if err != nil || !valid {
				t.Fatalf("%d leaves, proof %d: %v, %v", n, i, valid, err)
			}
			basicPath, basicSides, err := small.GetMerklePathByIndex(i)
			if err != nil || len(path) != len(basicPath) || len(sides) != len(basicSides) {
				t.Fatalf("%d leaves, proof %d: path lengths differ: %v", n, i, err)
			}
			for k := range path {
				if sides[k] != basicSides[k] || !bytes.Equal(path[k], basicPath[k]) {
					t.Fatalf("%d leaves, proof %d, step %d: path differs", n, i, k)
				}
			}
		}
	}
}

type sha512Content string

func (c sha512Content) CalculateHash() ([]byte, error) {
	h := sha512.Sum512([]byte(c))
	return h[:], nil
}

func (c sha512Content) Equals(other merkletree.Content) (bool, error) {
	o, ok := other.(sha512Content)
	return ok && c == o, nil
}

func TestBasicCustomHasherMatchesFull(t *testing.T) {
	contents := []merkletree.Content{sha512Content("a"), sha512Content("b"), sha512Content("c")}
	leaves := make([][]byte, len(contents))
	for i, c := range contents {
		leaves[i], _ = c.CalculateHash()
	}
	strategy := func() hash.Hash { return sha512.New() }
	small, err := basic.NewTreeWithHashStrategy(leaves, strategy)
	if err != nil {
		t.Fatal(err)
	}
	full, err := merkletree.NewTreeWithHashStrategy(contents, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(small.MerkleRoot(), full.MerkleRoot()) {
		t.Fatal("custom hasher roots differ")
	}
}

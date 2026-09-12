package main

import (
	mathrand "math/rand"
	"testing"
)

func TestShuffledScenariosIsDeterministicAndComplete(t *testing.T) {
	first := shuffledScenarios(mathrand.New(mathrand.NewSource(42)))
	second := shuffledScenarios(mathrand.New(mathrand.NewSource(42)))
	if len(first) != 5 || len(second) != len(first) {
		t.Fatalf("scenario lengths = %d and %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("same seed produced different order: %v vs %v", first, second)
		}
	}
	seen := map[string]bool{}
	for _, scenario := range first {
		if seen[scenario] {
			t.Fatalf("duplicate scenario %q in %v", scenario, first)
		}
		seen[scenario] = true
	}
	if len(seen) != 5 {
		t.Fatalf("scenario set = %v", seen)
	}
}

func TestShuffledNamesIsDeterministicAndComplete(t *testing.T) {
	first := shuffledNames(mathrand.New(mathrand.NewSource(42)))
	second := shuffledNames(mathrand.New(mathrand.NewSource(42)))
	if len(first) != 2 || first[0] == first[1] || first[0] != second[0] || first[1] != second[1] {
		t.Fatalf("same seed produced invalid name order: %v vs %v", first, second)
	}
}

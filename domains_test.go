package main

import (
	"reflect"
	"testing"
)

func TestDomainsCollectsEveryFlagAndCommaList(t *testing.T) {
	args := parseArgs([]string{"--domain", "Example.com,www.example.com", "--domain", "api.example.com.", "--domain", "example.com"})
	got, err := domains(args)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "www.example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDomainsRejectsAnInvalidName(t *testing.T) {
	if _, err := domains(parseArgs([]string{"--domain", "example.com,bad_name"})); err == nil {
		t.Fatal("bad_name accepted")
	}
}

func TestDomainsEmptyClearsTheList(t *testing.T) {
	got, err := domains(parseArgs([]string{"--domain="}))
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

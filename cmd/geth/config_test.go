package main

import (
	"flag"
	"testing"

	"github.com/urfave/cli/v2"
)

func TestMakeConfigNode(t *testing.T) {
	// Create a CLI context with the required flags
	app := cli.NewApp()
	set := flag.NewFlagSet("test", 0)
	set.String("gcmode", "full", "Blockchain garbage collection mode")
	set.String("crypto.kzg", "gokzg", "KZG library implementation to use")
	ctx := cli.NewContext(app, set, nil)
	// Set the flags
	err := set.Set("gcmode", "full")
	if err != nil {
		t.Fatalf("Failed to set gcmode flag: %v", err)
	}
	err = set.Set("crypto.kzg", "gokzg")
	if err != nil {
		t.Fatalf("Failed to set crypto.kzg flag: %v", err)
	}
	// Call the function you want to test
	// node, cfg := makeConfigNode(ctx)
	backend, eth := MakeFullNodeGethPROF(ctx)
	// Test backend
	if backend == nil {
		t.Fatal("Backend is nil")
	}
	// Test eth
	if eth == nil {
		t.Fatal("Ethereum object is nil")
	}
}

// Command chaos-harness runs one catalog scenario and prints a JSON result.
// Status is passed, failed, or error. A missing observation is failed.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/agentshield/agentshield/runtime/gateway/internal/chaos"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "scenario id required")
		os.Exit(2)
	}
	encoded, err := json.Marshal(chaos.Run(os.Args[1]))
	if err != nil {
		fmt.Fprintln(os.Stderr, "result encoding failed")
		os.Exit(1)
	}
	fmt.Println(string(encoded))
}

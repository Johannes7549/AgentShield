// Package adapter contains tool handlers the gateway is willing to call.
// sample.echo has no external side effect. Any other tool is unsupported.
package adapter

const SampleEcho = "sample.echo"

type SampleResult struct {
	Adapter   string `json:"adapter"`
	Label     string `json:"label"`
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
}

func Echo(operation string, resource string) (SampleResult, bool) {
	if operation != SampleEcho {
		return SampleResult{}, false
	}
	return SampleResult{
		Adapter:   SampleEcho,
		Label:     "sample adapter with no external side effect",
		Operation: operation,
		Resource:  resource,
	}, true
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"essaim.dev/al"
)

// Status represents the current Link state
type Status struct {
	NumPeers  uint64  `json:"num_peers"`
	Tempo     float64 `json:"tempo"`
	Timestamp string  `json:"timestamp"`
}

func main() {
	// Command line flags
	setTempo := flag.Float64("set-tempo", 0, "Set tempo to this BPM (0 = don't change)")
	initialTempo := flag.Float64("initial-tempo", 120.0, "Initial tempo when creating Link instance")
	reportInterval := flag.Duration("interval", time.Second, "Status report interval")
	duration := flag.Duration("duration", 0, "Run for this duration then exit (0 = run forever)")
	outputJSON := flag.Bool("json", false, "Output status as JSON")

	flag.Parse()

	// Create Link instance
	link := al.NewLink(*initialTempo)
	defer link.Close()

	// Enable Link
	link.Enable(true)

	// Give Link time to initialize
	time.Sleep(100 * time.Millisecond)

	// Set tempo if requested - use NewSessionState() constructor
	if *setTempo > 0 {
		state := al.NewSessionState()
		defer state.Close()
		link.CaptureAppSessionState(state)
		state.SetTempo(*setTempo, link.Clock())
		link.CommitAppSessionState(state)
		if !*outputJSON {
			fmt.Printf("Set tempo to %.2f BPM\n", *setTempo)
		}
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Set up duration timer if specified
	var durationTimer <-chan time.Time
	if *duration > 0 {
		durationTimer = time.After(*duration)
	}

	// Status reporting ticker
	ticker := time.NewTicker(*reportInterval)
	defer ticker.Stop()

	getStatus := func() Status {
		state := al.NewSessionState()
		link.CaptureAppSessionState(state)
		tempo := state.Tempo()
		numPeers := link.NumPeers()
		state.Close()

		return Status{
			NumPeers:  numPeers,
			Tempo:     tempo,
			Timestamp: time.Now().Format(time.RFC3339Nano),
		}
	}

	printStatus := func(status Status) {
		if *outputJSON {
			data, _ := json.Marshal(status)
			fmt.Println(string(data))
		} else {
			fmt.Printf("[%s] Peers: %d | Tempo: %.2f BPM\n",
				status.Timestamp, status.NumPeers, status.Tempo)
		}
	}

	// Print initial status
	printStatus(getStatus())

	for {
		select {
		case <-sigChan:
			fmt.Fprintln(os.Stderr, "Shutting down...")
			return

		case <-durationTimer:
			if !*outputJSON {
				fmt.Fprintln(os.Stderr, "Duration reached, exiting...")
			}
			printStatus(getStatus())
			return

		case <-ticker.C:
			printStatus(getStatus())
		}
	}
}

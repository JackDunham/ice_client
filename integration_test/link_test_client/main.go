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
	Beat      float64 `json:"beat"`
	Phase     float64 `json:"phase"`
	IsPlaying bool    `json:"is_playing"`
	Timestamp string  `json:"timestamp"`
}

func main() {
	// Command line flags
	setTempo := flag.Float64("set-tempo", 0, "Set tempo to this BPM (0 = don't change)")
	initialTempo := flag.Float64("initial-tempo", 120.0, "Initial tempo when creating Link instance")
	reportInterval := flag.Duration("interval", time.Second, "Status report interval")
	duration := flag.Duration("duration", 0, "Run for this duration then exit (0 = run forever)")
	outputJSON := flag.Bool("json", false, "Output status as JSON")
	waitForPeers := flag.Int("wait-for-peers", 0, "Wait until this many peers are connected, then exit")
	waitTimeout := flag.Duration("wait-timeout", 30*time.Second, "Timeout when waiting for peers")

	flag.Parse()

	// Create Link instance
	link := al.NewLink(*initialTempo)
	defer link.Close()

	// Enable Link
	link.Enable(true)
	link.EnableStartStopSync(true)

	// Set up peer count callback for logging
	link.SetNumPeersCallback(func(numPeers uint64) {
		if !*outputJSON {
			fmt.Printf("[%s] Peer count changed: %d\n", time.Now().Format(time.RFC3339), numPeers)
		}
	})

	// Set tempo if requested
	if *setTempo > 0 {
		state := &al.SessionState{}
		link.CaptureAppSessionState(state)
		state.SetTempo(*setTempo, time.Now())
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

	// Set up wait-for-peers timeout
	var waitTimer <-chan time.Time
	if *waitForPeers > 0 {
		waitTimer = time.After(*waitTimeout)
	}

	// Status reporting ticker
	ticker := time.NewTicker(*reportInterval)
	defer ticker.Stop()

	getStatus := func() Status {
		state := &al.SessionState{}
		link.CaptureAppSessionState(state)
		now := time.Now()

		return Status{
			NumPeers:  link.NumPeers(),
			Tempo:     state.Tempo(),
			Beat:      state.BeatAtTime(now, 4.0),
			Phase:     state.PhaseAtTime(now, 4.0),
			IsPlaying: state.IsPlaying(),
			Timestamp: now.Format(time.RFC3339Nano),
		}
	}

	printStatus := func(status Status) {
		if *outputJSON {
			data, _ := json.Marshal(status)
			fmt.Println(string(data))
		} else {
			fmt.Printf("[%s] Peers: %d | Tempo: %.2f BPM | Beat: %.2f | Phase: %.2f | Playing: %v\n",
				status.Timestamp, status.NumPeers, status.Tempo, status.Beat, status.Phase, status.IsPlaying)
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

		case <-waitTimer:
			fmt.Fprintln(os.Stderr, "Timeout waiting for peers")
			os.Exit(1)

		case <-ticker.C:
			status := getStatus()
			printStatus(status)

			// Check if we've reached the desired peer count
			if *waitForPeers > 0 && int(status.NumPeers) >= *waitForPeers {
				if !*outputJSON {
					fmt.Fprintf(os.Stderr, "Reached %d peers, exiting successfully\n", *waitForPeers)
				}
				os.Exit(0)
			}
		}
	}
}

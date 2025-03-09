package main

import (
	"context"
	"fmt"
	"ice-client/multicast"
	"log"
	"os"
	"time"
)

func main() {
	ctx := context.Background()
	// Create a channel to receive OS signals.
	quit := make(chan os.Signal, 1)

	// Use ListenConfig to bind with reuse options.
	lc := multicast.CreateListenConfig()

	// Bind one UDP socket on all interfaces (0.0.0.0) at port 20808.
	pc, err := lc.ListenPacket(ctx, "udp4", multicast.LinkPort)
	if err != nil {
		log.Fatalf("Failed to bind UDP socket: %v", err)
	}
	defer pc.Close()

	// Wrap the connection with ipv4.PacketConn to manage multicast.
	p, multicastIP, err := multicast.GetMulticastPacketConnection(pc, multicast.UDP4MulticastAddress)
	if err != nil {
		log.Fatalf("Error getting multicast connection: %s", err.Error())
	}

	// Join the multicast group on all eligible interfaces.
	multicast.JoinMulticastGroups(p, multicastIP)
	rxChan := make(chan multicast.PacketAndMep4, 1024)
	go multicast.ListenForLinkPackets(ctx, p, multicastIP, multicast.LinkHeader, rxChan)
	go func(rxChan chan multicast.PacketAndMep4) {
		for linkPacket := range rxChan {
			fmt.Printf("LinkPacket %+v", linkPacket)
		}
	}(rxChan)
	// TEST that we can actually SEND a link-packet
	time.Sleep(time.Minute)
	multicast.SendLinkPacket(p, multicastIP, []byte("DERPDERPDERP"))
	log.Print("waiting for sig-quit")
	<-quit
	log.Print("quitting")
}

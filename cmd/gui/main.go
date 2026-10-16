package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"unicompute/pkg/gui"
)

func main() {
	portFlag := flag.Int("port", 9099, "Loopback HTTP port for embedded Studio UI")
	headlessFlag := flag.Bool("headless", false, "Run in headless/server-only mode without native WebView2 window")
	vaultFlag := flag.String("vault", "", "Storage vault directory path (defaults to system temp)")
	flag.Parse()

	app, err := gui.NewStudioApp(*vaultFlag)
	if err != nil {
		log.Fatalf("Fatal: failed to initialize UniCompute Studio: %v", err)
	}
	defer app.Close()

	srv, err := gui.StartServer(app, *portFlag)
	if err != nil {
		log.Fatalf("Fatal: failed to start embedded HTTP server: %v", err)
	}
	defer srv.Close()

	fmt.Println("==================================================================")
	fmt.Println(" UniCompute Dual-Mode Desktop Studio (v2.4.1) Online")
	fmt.Printf(" UI Dashboard URL: %s\n", srv.URL)
	fmt.Println(" Mode 1: Donor Node Agent (Win32 JobObject & Battery Guard)")
	fmt.Println(" Mode 2: Researcher Studio (FastCDC + MLE + 4-Stage DAG Visualizer)")
	fmt.Println(" Mode 3: Storage Vault Explorer (80-Shard Cauchy RS(32, 80) Matrix)")
	fmt.Println("==================================================================")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[Studio] Shutting down...")
		app.Close()
		os.Exit(0)
	}()

	win, err := gui.NewDesktopWindow(app, srv.URL, *headlessFlag)
	if err != nil {
		log.Printf("[Studio] Warning creating desktop window: %v. Running in server mode.", err)
	} else {
		defer win.Close()
	}

	if win != nil {
		win.Run()
	} else {
		select {}
	}
}

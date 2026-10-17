//go:build windows

package gui

import (
	"log"
	"os"
	"os/exec"

	"github.com/jchv/go-webview2"

	"unicompute/pkg/protocol"
	"unicompute/pkg/web"
)

// DesktopWindow wraps the native Windows WebView2 application window or standalone app host.
type DesktopWindow struct {
	wv        webview2.WebView
	app       *StudioApp
	serverURL string
	headless  bool
	appCmd    *exec.Cmd
}

// NewDesktopWindow creates a native Windows WebView2 desktop window or standalone app window.
func NewDesktopWindow(app *StudioApp, serverURL string, headless bool) (*DesktopWindow, error) {
	dw := &DesktopWindow{
		app:       app,
		serverURL: serverURL,
		headless:  headless,
	}

	if headless {
		log.Println("[Desktop Window] Running in headless / server-only mode.")
		return dw, nil
	}

	// Create WebView2 native window
	wv := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     true,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "UniCompute Desktop Studio (v2.4.1)",
			Width:  1280,
			Height: 860,
			IconId: 0,
			Center: true,
		},
	})

	if wv == nil {
		log.Println("[Desktop Window] Launching native standalone desktop app window via Microsoft Edge App Mode...")
		dw.appCmd = OpenNativeAppWindow(serverURL)
		return dw, nil
	}

	dw.wv = wv
	wv.SetTitle("UniCompute Desktop Studio (v2.4.1)")
	wv.SetSize(1280, 860, webview2.HintNone)

	// Attach System Tray to the window's HWND
	if hwnd := wv.Window(); hwnd != nil {
		tray := NewTrayManager(uintptr(hwnd))
		app.SetTrayManager(tray)
	}

	// Bind in-process Go methods to JavaScript
	_ = wv.Bind("GetSystemStats", func() (SystemStats, error) {
		return app.GetSystemStats()
	})
	_ = wv.Bind("UpdateResourceSliders", func(cores int, ramMB int64, storageGB int64) error {
		return app.UpdateResourceSliders(cores, ramMB, storageGB)
	})
	_ = wv.Bind("TogglePause", func() (bool, error) {
		return app.TogglePause()
	})
	_ = wv.Bind("UpdateRules", func(battery, gaming, hours bool) error {
		return app.UpdateRules(battery, gaming, hours)
	})
	_ = wv.Bind("GetDAGStatus", func() (DAGPipelineStatus, error) {
		return app.GetDAGStatus()
	})
	_ = wv.Bind("GetVaultStatus", func() (VaultMatrixStatus, error) {
		return app.GetVaultStatus()
	})
	_ = wv.Bind("MinimizeToTray", func() error {
		app.MinimizeToTray()
		return nil
	})
	_ = wv.Bind("RestoreWindow", func() error {
		app.RestoreWindow()
		return nil
	})
	_ = wv.Bind("StartWorker", func(cfg WorkerConnectionConfig) error {
		return app.StartWorker(cfg)
	})
	_ = wv.Bind("StopWorker", func() error {
		return app.StopWorker()
	})
	_ = wv.Bind("ReconnectWorker", func() error {
		return app.ReconnectWorker()
	})
	_ = wv.Bind("GetWorkerStatus", func() WorkerConnectionStatus {
		return app.GetWorkerStatus()
	})
	_ = wv.Bind("GetWorkerReceipts", func() []*protocol.ExecutionReceipt {
		return app.GetWorkerReceipts()
	})
	_ = wv.Bind("PublishManifest", func(req PublishManifestRequest) (PublishManifestResponse, error) {
		return app.PublishManifest(req)
	})
	_ = wv.Bind("GetClusterStatus", func(coordURL string) (*web.ClusterStatusResponse, error) {
		return app.GetClusterStatus(coordURL)
	})
	_ = wv.Bind("GetClusterFleet", func(coordURL string) ([]web.FleetNodeStatus, error) {
		return app.GetClusterFleet(coordURL)
	})

	// Navigate to embedded Studio UI
	wv.Navigate(serverURL)

	return dw, nil
}

// Run starts the native Windows message and event loop.
func (dw *DesktopWindow) Run() {
	if dw.wv != nil {
		dw.wv.Run()
		return
	}

	if dw.appCmd != nil && dw.appCmd.Process != nil {
		_ = dw.appCmd.Wait()
		return
	}

	// In headless mode, wait on app termination
	<-dw.app.stopCh
}

// Close destroys the native window.
func (dw *DesktopWindow) Close() {
	if dw.wv != nil {
		dw.wv.Destroy()
	}
	if dw.appCmd != nil && dw.appCmd.Process != nil {
		_ = dw.appCmd.Process.Kill()
	}
}

// OpenNativeAppWindow launches Microsoft Edge in standalone app window mode or default system browser.
func OpenNativeAppWindow(url string) *exec.Cmd {
	edgePaths := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`msedge.exe`,
	}

	for _, p := range edgePaths {
		if _, err := os.Stat(p); err == nil || p == "msedge.exe" {
			cmd := exec.Command(p, "--app="+url, "--window-size=1280,860", "--new-window")
			if err := cmd.Start(); err == nil {
				log.Printf("[Desktop Window] Launched native standalone app window via %s", p)
				return cmd
			}
		}
	}

	// Fallback to default browser via rundll32
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	_ = cmd.Start()
	return cmd
}

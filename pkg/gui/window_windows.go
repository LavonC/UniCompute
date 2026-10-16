//go:build windows

package gui

import (
	"log"

	"github.com/jchv/go-webview2"
)

// DesktopWindow wraps the native Windows WebView2 application window.
type DesktopWindow struct {
	wv        webview2.WebView
	app       *StudioApp
	serverURL string
	headless  bool
}

// NewDesktopWindow creates a native Windows WebView2 desktop window.
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
			IconId: 32512, // IDI_APPLICATION
			Center: true,
		},
	})

	if wv == nil {
		log.Println("[Desktop Window] Notice: WebView2 runtime unavailable, defaulting to server mode.")
		dw.headless = true
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

	// Navigate to embedded Studio UI
	wv.Navigate(serverURL)

	return dw, nil
}

// Run starts the native Windows message and event loop.
func (dw *DesktopWindow) Run() {
	if dw.headless || dw.wv == nil {
		// In headless mode, wait on app termination
		<-dw.app.stopCh
		return
	}

	dw.wv.Run()
}

// Close destroys the native window.
func (dw *DesktopWindow) Close() {
	if dw.wv != nil {
		dw.wv.Destroy()
	}
}

//go:build !windows

package gui

import (
	"log"
)

// DesktopWindow fallback stub for non-Windows platforms.
type DesktopWindow struct {
	app       *StudioApp
	serverURL string
}

func NewDesktopWindow(app *StudioApp, serverURL string, headless bool) (*DesktopWindow, error) {
	log.Printf("[Desktop Window] Running Studio server on %s", serverURL)
	return &DesktopWindow{app: app, serverURL: serverURL}, nil
}

func (dw *DesktopWindow) Run() {
	<-dw.app.stopCh
}

func (dw *DesktopWindow) Close() {}

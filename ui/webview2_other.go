//go:build wails && !windows

package main

// checkWebView2 solo hace falta en Windows (ui/webview2_windows.go): en Linux WebKitGTK es dependencia del paquete.
func checkWebView2() {}

// webviewUserDataPath solo aplica a WebView2 (Windows).
func webviewUserDataPath() string { return "" }

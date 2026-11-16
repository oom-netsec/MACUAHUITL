//go:build wails && !windows

package main

// redirectLog: en Linux la app escribe a stderr, que el escritorio manda al journal de la sesión.
func redirectLog() {}

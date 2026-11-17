package sys

import "golang.org/x/sys/windows"

// ShortPath da el nombre corto 8.3 de p, o "" si el volumen no los tiene.
func ShortPath(p string) string {
	long, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return ""
	}
	buf := make([]uint16, 512)
	n, err := windows.GetShortPathName(long, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

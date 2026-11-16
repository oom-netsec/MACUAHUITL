package sys

// RedirectStderr no hace nada en Linux: el núcleo escribe a stderr y systemd lo manda al journal.
func RedirectStderr(string) error { return nil }

// LogFailure no hace nada en Linux, por lo mismo.
func LogFailure(string, string) {}

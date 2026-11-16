package i18n

// Errores de serialcon que solo existen en Windows (nombres COMn).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"serial.err.path_win": e("serialcon: {path:q} no es un puerto COM (por ejemplo COM3)", "serialcon: {path:q} is not a COM port (for example COM3)", "path"),
	})
}

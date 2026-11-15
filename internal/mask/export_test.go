package mask

// Cut expone cut a las pruebas externas.
func Cut(orig, s1 string, spans [][2]int) (string, int) { return cut(orig, s1, spans) }

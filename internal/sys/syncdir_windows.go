package sys

// SyncDir no hace nada en Windows y devuelve nil. os.Open(carpeta).Sync() da «Access is denied»: FlushFileBuffers sobre
// un directorio exige un handle con escritura y FILE_FLAG_BACKUP_SEMANTICS, y aun así no tiene durabilidad documentada.
// El contenido de cada archivo sí se sincroniza (File.Sync). Límite: tras un corte de luz el rename puede perderse
// (el journal de NTFS no se vacía en el momento del rename) y queda la versión anterior, completa; si hiciera falta,
// MoveFileEx con MOVEFILE_WRITE_THROUGH en el rename.
func SyncDir(string) error { return nil }

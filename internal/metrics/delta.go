package metrics

// octetRate da los bits por segundo entre dos lecturas de un contador de octetos. No adivina
// (misma regla que la del sondeo SNMP de diag/snmp): sin tasa si dt no es positivo, si el
// contador bajó y no es la vuelta de uno de 32 bits, si pudo dar más de una vuelta en dt a la
// velocidad del puerto, o si el resultado supera esa velocidad (con 5 % de holgura por el reloj).
// bwKbit es el "BW" del equipo; 0 = no se conoce: no se aceptan vueltas (sin la velocidad no se
// sabe si fue una vuelta o un `clear counters`) y el tope de velocidad no aplica.
//
// Un `clear counters` desde un valor entre 2^31 y 2^32 se parece a una vuelta; ratePoint lo descarta
// antes con la hora de la última limpieza (Iface.ClearAgo), y aquí solo lo frena el tope de velocidad.
func octetRate(prev, cur int64, dt float64, bwKbit int64) (float64, bool) {
	if dt <= 0 || prev < 0 || cur < 0 {
		return 0, false
	}
	speed := float64(bwKbit) * 1000
	var d int64
	switch {
	case cur >= prev:
		d = cur - prev
	case prev >= 1<<31 && prev < 1<<32 && speed > 0: // pudo ser un contador de 32 bits que dio la vuelta
		if dt >= float64(uint64(1)<<32)*8/speed {
			return 0, false // más de una vuelta posible: no se sabe cuántas
		}
		d = 1<<32 - prev + cur
	default:
		return 0, false // reinicio o clear counters
	}
	r := float64(d) * 8 / dt
	if speed > 0 && r > speed*1.05 {
		return 0, false
	}
	return r, true
}

// counterDelta es la diferencia entre rondas de un contador de eventos (errores, descartes, CRC,
// resets). Si bajó, el equipo se reinició o se limpiaron los contadores: no hay diferencia.
func counterDelta(prev, cur int64) (int64, bool) {
	if cur < prev {
		return 0, false
	}
	return cur - prev, true
}

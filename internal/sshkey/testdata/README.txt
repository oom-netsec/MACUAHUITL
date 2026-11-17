Llaves de prueba descartables, generadas con ssh-keygen real (OpenSSH) para probar la interoperabilidad de Import.
Frase de las dos: frase-de-prueba.
k_ed25519: ssh-keygen -t ed25519 -N frase-de-prueba (formato OpenSSH, bcrypt-pbkdf + aes256-ctr).
k_rsa:     ssh-keygen -t rsa -b 2048 -m PEM -N frase-de-prueba (PKCS#1 con cifrado PEM legado AES-128-CBC).
No protegen nada: no las uses en ningún equipo.

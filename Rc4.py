# -*- coding: utf-8 -*-
"""
Parte 3 - Algoritmo RC4 (version con parametros exactos del enunciado)

Diccionario D (64 caracteres -> 6 bits por caracter):
D = ABCDEFGHIJKLMNÑOPQRSTUVWXYZÁÉÍÓÚabcdefghijklmnñopqrstuvwxyzáéíóú
"""

D = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZÁÉÍÓÚabcdefghijklmnñopqrstuvwxyzáéíóú"
assert len(D) == 64, f"El diccionario tiene {len(D)} caracteres, deberia tener 64"

CHAR2IDX = {c: i for i, c in enumerate(D)}
IDX2CHAR = {i: c for i, c in enumerate(D)}


def encode_message(msg: str):
    """Convierte un mensaje (usando solo caracteres del diccionario D) en una lista de indices 0-63."""
    idx = []
    for ch in msg:
        if ch not in CHAR2IDX:
            raise ValueError(f"El caracter '{ch}' no pertenece al diccionario D de 64 simbolos")
        idx.append(CHAR2IDX[ch])
    return idx


def indices_to_str(indices):
    return ''.join(IDX2CHAR[i] for i in indices)


def bits_str(indices, nbits=6):
    """Convierte una lista de indices (0-63) en su representacion binaria de 6 bits cada uno, concatenada."""
    return ''.join(format(i, f'0{nbits}b') for i in indices)


def bits_str_grouped(indices, nbits=6):
    """Igual que bits_str pero separando cada caracter con un espacio (para lectura en el informe)."""
    return ' '.join(format(i, f'0{nbits}b') for i in indices)


# ---------------------------- RC4 (KSA + PRGA) sobre N=64 ----------------------------
def rc4_ksa(key_indices, n=64):
    """Key Scheduling Algorithm adaptado a un S-box de tamano N=64 (en vez de 256)."""
    S = list(range(n))
    j = 0
    klen = len(key_indices)
    for i in range(n):
        j = (j + S[i] + key_indices[i % klen]) % n
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga(S, n_symbols, n=64):
    """Pseudo-Random Generation Algorithm: genera n_symbols valores de keystream (0-63 cada uno)."""
    S = S[:]  # no modificar el S-box original
    i = j = 0
    out = []
    for _ in range(n_symbols):
        i = (i + 1) % n
        j = (j + S[i]) % n
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % n]
        out.append(k)
    return out


def rc4_keystream(key: str, n_symbols: int):
    key_idx = encode_message(key)
    if not (4 <= len(key) <= 32):
        raise ValueError("La clave debe tener entre 4 y 32 caracteres")
    S = rc4_ksa(key_idx)
    return rc4_prga(S, n_symbols)


def rc4_encrypt(key: str, msg: str):
    msg_idx = encode_message(msg)
    ks = rc4_keystream(key, len(msg_idx))
    ct_idx = [m ^ k for m, k in zip(msg_idx, ks)]
    return msg_idx, ks, ct_idx


def rc4_decrypt_indices(key: str, ct_idx):
    ks = rc4_keystream(key, len(ct_idx))
    return [c ^ k for c, k in zip(ct_idx, ks)]


# ---------------------------- Analisis de postulados de Golomb ----------------------------
def golomb_analysis(bitstring: str):
    n = len(bitstring)
    ones = bitstring.count('1')
    zeros = n - ones

    # Postulado 1: balance (|#unos - #ceros| <= 1)
    balance_diff = abs(ones - zeros)

    # Postulado 2: distribucion de rachas (runs)
    runs = []
    i = 0
    while i < n:
        j = i
        while j < n and bitstring[j] == bitstring[i]:
            j += 1
        runs.append(j - i)
        i = j
    from collections import Counter
    run_counts = Counter(runs)
    total_runs = len(runs)
    run_dist_pct = {L: round(100 * c / total_runs, 2) for L, c in sorted(run_counts.items())}

    # Postulado 3: autocorrelacion fuera de fase
    def autocorr(bits, k):
        eq = sum(1 for idx in range(n) if bits[idx] == bits[(idx + k) % n])
        return (eq - (n - eq)) / n

    max_k = min(20, n - 1)
    autocorrs = [round(autocorr(bitstring, k), 4) for k in range(1, max_k + 1)]

    return {
        "longitud_bits": n,
        "unos": ones,
        "ceros": zeros,
        "diferencia_unos_ceros": balance_diff,
        "cumple_postulado1_balance": balance_diff <= 1,
        "total_rachas": total_runs,
        "distribucion_rachas_pct": run_dist_pct,
        "autocorrelaciones_k1_a_k20": autocorrs,
    }


if __name__ == "__main__":
    print("=" * 78)
    print("PARAMETROS")
    print("=" * 78)
    print(f"Diccionario D ({len(D)} caracteres):")
    print(D)
    print()

    MENSAJE = "MensajeDePruebaDeCifradoDeFlujoParaCriptología"
    print(f"Mensaje a codificar: {MENSAJE}")
    print(f"Longitud del mensaje: {len(MENSAJE)} caracteres")
    # validar que todos los caracteres del mensaje estan en D
    faltantes = [c for c in MENSAJE if c not in CHAR2IDX]
    print(f"Caracteres del mensaje NO presentes en D: {faltantes if faltantes else 'ninguno (OK)'}")
    print()

    # =====================================================================
    # PUNTO 2: Codificar el mensaje con la clave "ClaveSegura"
    # =====================================================================
    print("=" * 78)
    print("PUNTO 2 - Prueba de funcionamiento con clave 'ClaveSegura'")
    print("=" * 78)
    CLAVE = "ClaveSegura"
    print(f"Clave: {CLAVE}  (longitud {len(CLAVE)}, dentro del rango 4-32 permitido)")

    msg_idx, ks, ct_idx = rc4_encrypt(CLAVE, MENSAJE)

    print("\n--- Indices (0-63) del mensaje segun el diccionario D ---")
    print(msg_idx)

    print("\n--- KeyStream (valores 0-63) ---")
    print(ks)

    print("\n--- KeyStream en BINARIO (6 bits por simbolo) ---")
    ks_bits = bits_str(ks)
    print("Concatenado:", ks_bits)
    print("Agrupado de a 6 bits:", bits_str_grouped(ks))

    print("\n--- Mensaje codificado en BINARIO (6 bits por caracter, segun D) ---")
    msg_bits = bits_str(msg_idx)
    print("Concatenado:", msg_bits)
    print("Agrupado de a 6 bits:", bits_str_grouped(msg_idx))

    print("\n--- XOR (mensaje binario XOR keystream binario) ---")
    ct_bits = bits_str(ct_idx)
    print("Concatenado:", ct_bits)
    print("Agrupado de a 6 bits:", bits_str_grouped(ct_idx))

    print("\n--- Mensaje CIFRADO (los mismos bits del XOR, reinterpretados con el diccionario D) ---")
    criptograma = indices_to_str(ct_idx)
    print(criptograma)

    # verificacion de descifrado
    back_idx = rc4_decrypt_indices(CLAVE, ct_idx)
    print("\nVerificacion: descifrar con la misma clave recupera el mensaje original:",
          indices_to_str(back_idx) == MENSAJE)

    # =====================================================================
    # Analisis de postulados de Golomb sobre el KeyStream
    # =====================================================================
    print("\n" + "=" * 78)
    print("ANALISIS DE POSTULADOS DE GOLOMB (sobre el KeyStream en binario)")
    print("=" * 78)
    analysis = golomb_analysis(ks_bits)
    for k, v in analysis.items():
        print(f"{k}: {v}")

    # =====================================================================
    # PUNTO 3: Codificar el mensaje con una clave propia
    # =====================================================================
    print("\n" + "=" * 78)
    print("PUNTO 3 - Codificar con una clave propia")
    print("=" * 78)
    CLAVE_PROPIA = "SeguridadTotal"
    print(f"Clave propia elegida: {CLAVE_PROPIA} (longitud {len(CLAVE_PROPIA)})")
    msg_idx2, ks2, ct_idx2 = rc4_encrypt(CLAVE_PROPIA, MENSAJE)
    criptograma2 = indices_to_str(ct_idx2)
    print("Mensaje cifrado con clave propia:", criptograma2)

    print("\n--- 3.1 Descifrar usando la clave correcta ---")
    dec_ok_idx = rc4_decrypt_indices(CLAVE_PROPIA, ct_idx2)
    dec_ok = indices_to_str(dec_ok_idx)
    print("Resultado del descifrado:", dec_ok)
    print("Coincide con el mensaje original:", dec_ok == MENSAJE)

    print("\n--- 3.2 Descifrar cambiando 1 caracter de la clave (implementacion detallada) ---")
    CLAVE_MODIFICADA = "SeguridadTotak"  # se cambio la 'l' final por 'k'
    print(f"Clave modificada: {CLAVE_MODIFICADA}  (se cambio 1 caracter respecto a '{CLAVE_PROPIA}')")

    # Criptograma que se intenta descifrar (es el mismo ct_idx2 generado en el Punto 3, cifrado con la clave correcta)
    print("\nCriptograma a descifrar (indices 0-63):")
    print(ct_idx2)
    print("Criptograma en BINARIO (6 bits por simbolo):")
    ct2_bits = bits_str(ct_idx2)
    print("Concatenado:", ct2_bits)
    print("Agrupado de a 6 bits:", bits_str_grouped(ct_idx2))
    print("Criptograma en el diccionario D:", criptograma2)

    # KeyStream generado con la clave INCORRECTA
    ks_bad = rc4_keystream(CLAVE_MODIFICADA, len(ct_idx2))
    print("\nKeyStream generado con la clave incorrecta (indices 0-63):")
    print(ks_bad)
    print("KeyStream incorrecto en BINARIO (6 bits por simbolo):")
    ks_bad_bits = bits_str(ks_bad)
    print("Concatenado:", ks_bad_bits)
    print("Agrupado de a 6 bits:", bits_str_grouped(ks_bad))

    # XOR entre el criptograma y el keystream incorrecto = "descifrado" erroneo
    dec_bad_idx = [c ^ k for c, k in zip(ct_idx2, ks_bad)]
    print("\nXOR (criptograma binario XOR keystream-incorrecto binario):")
    dec_bad_bits = bits_str(dec_bad_idx)
    print("Concatenado:", dec_bad_bits)
    print("Agrupado de a 6 bits:", bits_str_grouped(dec_bad_idx))

    dec_bad = indices_to_str(dec_bad_idx)
    print("\nResultado del 'descifrado' con clave incorrecta (usando el diccionario D):", dec_bad)
    print("Coincide con el mensaje original:", dec_bad == MENSAJE)

    # comparacion directa contra el keystream correcto, para evidenciar la causa del error
    print("\n(Referencia) KeyStream generado con la clave CORRECTA (indices 0-63):")
    print(ks2)
    print("(Referencia) KeyStream correcto en BINARIO:")
    print(bits_str(ks2))

    # comparacion bit a bit del keystream generado por la clave correcta vs la modificada
    ks_ok_full = rc4_keystream(CLAVE_PROPIA, len(MENSAJE))
    ks_bad_full = rc4_keystream(CLAVE_MODIFICADA, len(MENSAJE))
    bits_ok = bits_str(ks_ok_full)
    bits_bad = bits_str(ks_bad_full)
    dist = sum(1 for a, b in zip(bits_ok, bits_bad) if a != b)
    print(f"\nBits distintos entre el keystream de la clave correcta y la modificada: "
          f"{dist} / {len(bits_ok)} ({100*dist/len(bits_ok):.1f}%)")

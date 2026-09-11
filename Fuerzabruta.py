# -*- coding: utf-8 -*-
"""
Ataque de fuerza bruta sobre RC4, usando el mismo diccionario D (64 simbolos)
y las mismas funciones de KSA/PRGA que en el Punto 3 (rc4_exacto.py).
"""
import time
import itertools
import re
from rc4_exacto import D, CHAR2IDX, IDX2CHAR, encode_message, indices_to_str, rc4_ksa, rc4_prga

# Palabras comunes del espanol usadas para detectar un descifrado "con sentido"
PALABRAS_COMUNES = {
    "el", "la", "los", "las", "de", "en", "es", "un", "una", "que", "por", "con",
    "para", "se", "su", "al", "del", "no", "como", "sol", "hoy", "brilla", "ataque",
    "fuerza", "bruta", "exitoso", "clave", "cifrado", "flujo", "datos", "prueba",
    "mensaje", "seguridad", "esta", "muy", "mas", "pero", "todo", "vida", "dia"
}

TOKEN_RE = re.compile(r'[A-ZÁÉÍÓÚÑ][a-záéíóúñ]*')


def rc4_keystream_len(key_indices, n_symbols, n=64):
    S = rc4_ksa(key_indices, n)
    return rc4_prga(S, n_symbols, n)


def rc4_decrypt_with_key_indices(key_indices, ct_idx):
    ks = rc4_keystream_len(key_indices, len(ct_idx))
    return [c ^ k for c, k in zip(ct_idx, ks)]


def es_texto_plausible(texto: str) -> bool:
    """Heuristica para mensajes SIN espacios, escritos en estilo CamelCase
    (igual que el mensaje del enunciado, ej. 'MensajeDePruebaDe...').
    1) separa el texto en 'palabras' usando las mayusculas como frontera
    2) cuenta cuantos de esos fragmentos son palabras reales del espanol
    Se exige al menos 2 fragmentos reconocidos como palabras comunes."""
    tokens = TOKEN_RE.findall(texto)
    if len(tokens) < 2:
        return False
    reconocidas = sum(1 for t in tokens if t.lower() in PALABRAS_COMUNES)
    return reconocidas >= 2


if __name__ == "__main__":
    # =====================================================================
    # Paso 1: clave real de 8 caracteres (dentro del diccionario D) y mensaje
    # =====================================================================
    CLAVE_REAL = "SeguraKY"                       # 8 caracteres, todos en D
    MENSAJE_REAL = "AtaqueDeFuerzaBrutaExitoso"    # sin espacios, con sentido, 26 caracteres

    assert 8 == len(CLAVE_REAL)
    assert all(c in CHAR2IDX for c in CLAVE_REAL)
    assert all(c in CHAR2IDX for c in MENSAJE_REAL)

    key_idx = encode_message(CLAVE_REAL)
    msg_idx = encode_message(MENSAJE_REAL)
    ks = rc4_keystream_len(key_idx, len(msg_idx))
    ct_idx = [m ^ k for m, k in zip(msg_idx, ks)]
    criptograma = indices_to_str(ct_idx)

    print("=" * 78)
    print("PASO 1 - Cifrado real con clave de 8 caracteres")
    print("=" * 78)
    print("Clave real:", CLAVE_REAL, f"({len(CLAVE_REAL)} caracteres)")
    print("Mensaje real:", MENSAJE_REAL, f"({len(MENSAJE_REAL)} caracteres)")
    print("Criptograma (en el diccionario D):", criptograma)
    print("Criptograma (indices 0-63):", ct_idx)

    # =====================================================================
    # Paso 2: calculo del espacio de claves (64 simbolos, longitudes 4 a 8)
    # =====================================================================
    print("\n" + "=" * 78)
    print("PASO 2 - Calculo del espacio de claves")
    print("=" * 78)
    total = 0
    for L in range(4, 9):
        n = 64 ** L
        total += n
        print(f"  longitud {L}: 64^{L} = {n:,}")
    print(f"  TOTAL (longitudes 4 a 8) = {total:,}  ~= {total:.3e}")
    print(f"  Solo longitud 8 (la usada realmente): 64^8 = {64**8:,} ~= {64**8:.3e}")

    # =====================================================================
    # Paso 3: fuerza bruta REAL y COMPLETA para una longitud reducida (demo),
    # para medir la velocidad real de la implementacion y luego extrapolar.
    # =====================================================================
    DEMO_LEN = 3
    DEMO_CLAVE = "Luz"                 # 3 caracteres, dentro del espacio de busqueda
    DEMO_MENSAJE = "ElSolBrillaHoy"    # sin espacios, con sentido, 14 caracteres

    dk_idx = encode_message(DEMO_CLAVE)
    dm_idx = encode_message(DEMO_MENSAJE)
    dks = rc4_keystream_len(dk_idx, len(dm_idx))
    dct_idx = [m ^ k for m, k in zip(dm_idx, dks)]
    dct_str = indices_to_str(dct_idx)

    print("\n" + "=" * 78)
    print(f"PASO 3 - Fuerza bruta REAL Y COMPLETA para longitud {DEMO_LEN} "
          f"(64^{DEMO_LEN} = {64**DEMO_LEN:,} claves)")
    print("=" * 78)
    print("Clave demo:", DEMO_CLAVE, " Mensaje demo:", DEMO_MENSAJE)
    print("Criptograma demo (diccionario D):", dct_str)

    candidatos = []
    t0 = time.time()
    count = 0
    for combo in itertools.product(range(64), repeat=DEMO_LEN):
        count += 1
        dec_idx = rc4_decrypt_with_key_indices(list(combo), dct_idx)
        texto = indices_to_str(dec_idx)
        if es_texto_plausible(texto):
            clave_str = ''.join(IDX2CHAR[i] for i in combo)
            candidatos.append((clave_str, texto))
    t1 = time.time()
    elapsed = t1 - t0
    rate = count / elapsed

    print(f"\nCombinaciones probadas: {count:,}  (100% del espacio de longitud {DEMO_LEN})")
    print(f"Tiempo total: {elapsed:.2f} s  ->  {rate:,.0f} claves/segundo")
    print(f"Candidatos con apariencia de texto con sentido: {len(candidatos)}")
    print("Lista completa de candidatos encontrados:")
    for clave_str, texto in candidatos:
        marca = "  <-- CLAVE CORRECTA" if clave_str == DEMO_CLAVE else ""
        print(f"  clave='{clave_str}'  ->  '{texto}'{marca}")
    encontrada = any(c == DEMO_CLAVE for c, _ in candidatos)
    print("¿La clave correcta quedo entre los candidatos plausibles?:", encontrada)

    # =====================================================================
    # Paso 4: extrapolacion de tiempos para longitudes 4 a 8
    # =====================================================================
    print("\n" + "=" * 78)
    print("PASO 4 - Extrapolacion de tiempo (a partir de la velocidad medida)")
    print("=" * 78)
    for L in range(4, 9):
        n = 64 ** L
        seg = n / rate
        dias = seg / 86400
        anios = dias / 365
        print(f"  longitud {L}: {n:,} claves -> {seg:,.1f} s = {dias:,.2f} dias = {anios:,.4f} anios "
              f"(1 CPU, Python puro)")

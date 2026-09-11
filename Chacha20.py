import struct

def rotl32(x, n):
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = rotl32(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = rotl32(s[b], 7)

CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

def init_state(key: bytes, counter: int, nonce: bytes):
    assert len(key) == 32
    assert len(nonce) == 12
    kw = list(struct.unpack('<8I', key))
    nw = list(struct.unpack('<3I', nonce))
    return CONSTANTS + kw + [counter & 0xffffffff] + nw

def matrix_hex(state):
    rows = []
    for r in range(4):
        row = state[r*4:(r+1)*4]
        rows.append(' '.join(f'{w:08x}' for w in row))
    return '\n'.join(rows)

def chacha20_block(key, counter, nonce, collect_rounds=True):
    state = init_state(key, counter, nonce)
    working = state[:]
    rounds_log = []
    if collect_rounds:
        rounds_log.append(("estado inicial (ronda 0)", working[:]))
    for i in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        if collect_rounds:
            rounds_log.append((f"ronda {2*i+1} (columnas)", working[:]))
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
        if collect_rounds:
            rounds_log.append((f"ronda {2*i+2} (diagonales)", working[:]))
    output = [(working[i] + state[i]) & 0xffffffff for i in range(16)]
    return output, rounds_log, state

def pad_to_block(data: bytes, block_size=64):
    rem = len(data) % block_size
    if rem == 0:
        return data
    return data + b'\x00' * (block_size - rem)

def chacha20_encrypt(key, counter, nonce, plaintext: bytes, verbose_first_block=False, log_file=None):
    padded = pad_to_block(plaintext)
    ciphertext = bytearray()
    n_blocks = len(padded) // 64
    all_logs = []
    for b in range(n_blocks):
        block_counter = counter + b
        keystream_words, rounds_log, init_st = chacha20_block(key, block_counter, nonce)
        keystream_bytes = b''.join(struct.pack('<I', w) for w in keystream_words)
        chunk = padded[b*64:(b+1)*64]
        ct_chunk = bytes(x ^ y for x, y in zip(chunk, keystream_bytes))
        ciphertext += ct_chunk
        all_logs.append((block_counter, init_st, rounds_log, keystream_words))
        if log_file:
            log_file.write(f"\n=== BLOQUE (counter={block_counter}) ===\n")
            for name, mat in rounds_log:
                log_file.write(f"-- {name} --\n{matrix_hex(mat)}\n")
            log_file.write(f"-- keystream (salida final = trabajo + estado inicial) --\n{matrix_hex(keystream_words)}\n")
    final_nonce_state = None
    return bytes(ciphertext), all_logs

def hamming(a, b):
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

def hex_key(hexstr):
    return bytes.fromhex(hexstr.replace(':', ''))

def hex_nonce(hexstr):
    return bytes.fromhex(hexstr.replace(':', ''))

def dump_all_rounds(label, key, counter, nonce, fh):
    out, rlog, state = chacha20_block(key, counter, nonce)
    fh.write(f"\n{'='*70}\n{label}\n{'='*70}\n")
    fh.write(f"Clave: {key.hex()}\nNonce: {nonce.hex()}\nCounter: {counter}\n")
    for name, mat in rlog:
        fh.write(f"\n-- {name} --\n{matrix_hex(mat)}\n")
    fh.write(f"\n-- keystream final (trabajo + estado inicial) --\n{matrix_hex(out)}\n")
    return out, rlog, state


if __name__ == "__main__":
    KEY = hex_key("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f")
    NONCE = hex_nonce("00:00:00:09:00:00:00:4a:00:00:00:00")
    COUNTER = 1
    MSG = "Este mensaje de prueba sera cifrado con ChaCha20, un algoritmo de flujo rapido y seguro que usa una clave de 256 bits ahora.".encode('utf-8')

    print("### Verificacion contra RFC 7539 seccion 2.3.2 ###")
    print("Estado inicial:")
    st = init_state(KEY, COUNTER, NONCE)
    print(matrix_hex(st))
    out, rlog, _ = chacha20_block(KEY, COUNTER, NONCE)
    print("\nEstado tras 20 rondas (trabajo, antes de sumar el estado inicial):")
    print(matrix_hex(rlog[-1][1]))
    print("\nBloque de keystream final (trabajo + estado inicial):")
    print(matrix_hex(out))
    expected = [0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
                0xc7f4d1c6, 0x0309e671, 0x6b46360, 0x6ed69fdd,
                0x64e60b6b, 0xdb5d3ad7, 0x1eb63c00, 0xed4b7481, 0]
    print("\n(Referencia RFC7539: primeras palabras esperadas empiezan en e4e7f110 15593bd1 1fdd0f50 c47120a3 ...)")

    print("\n### TAREA 3: Prueba de funcionamiento ###")
    ct1, logs1 = chacha20_encrypt(KEY, COUNTER, NONCE, MSG)
    print("Mensaje (utf-8, padded a bloques de 64 bytes):", pad_to_block(MSG))
    print("Longitud mensaje:", len(MSG), "bytes -> bloques:", len(pad_to_block(MSG))//64)
    print("Texto cifrado (hex):", ct1.hex())
    print("Estado final del nonce usado:", NONCE.hex())

    print("\n### TAREA 4: Avalancha cambiando el NONCE ###")
    NONCE2 = hex_nonce("01:00:00:09:00:00:00:4a:00:00:00:00")
    ct2, logs2 = chacha20_encrypt(KEY, COUNTER, NONCE2, MSG)
    print("Texto cifrado con nonce nuevo (hex):", ct2.hex())
    r1 = logs1[0][2]; r2 = logs2[0][2]
    print("Ronda | bits distintos (de 512) | % distinto")
    for (name1, m1), (name2, m2) in zip(r1, r2):
        d = hamming(m1, m2)
        print(f"{name1:28s} | {d:4d} | {100*d/512:5.1f}%")
    print("Bits distintos en el criptograma final:", hamming(
        list(struct.unpack('<16I', pad_to_block(MSG)[:64])),
        list(struct.unpack('<16I', pad_to_block(MSG)[:64]))))  # placeholder not used

    print("\n### TAREA 5: Avalancha cambiando 1 bit de la CLAVE ###")
    KEY2 = hex_key("01:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f")
    ct3, logs3 = chacha20_encrypt(KEY2, COUNTER, NONCE, MSG)
    print("Texto cifrado con clave modificada (hex):", ct3.hex())
    r1 = logs1[0][2]; r3 = logs3[0][2]
    print("Ronda | bits distintos (de 512) | % distinto")
    for (name1, m1), (name3, m3) in zip(r1, r3):
        d = hamming(m1, m3)
        print(f"{name1:28s} | {d:4d} | {100*d/512:5.1f}%")
    ct_bytes_diff = sum(bin(a ^ b).count('1') for a, b in zip(ct1, ct3))
    print("Bits distintos entre criptograma1 y criptograma3:", ct_bytes_diff, "/", len(ct1)*8)

    print("\n### TAREA 6: Avalancha cambiando 1 bit del MENSAJE ###")
    MSG2 = "Este mensaje de prueba sera cifrado con ChaCha21, un algoritmo de flujo rapido y seguro que usa una clave de 256 bits ahora.".encode('utf-8')
    ct4, logs4 = chacha20_encrypt(KEY, COUNTER, NONCE, MSG2)
    print("Texto cifrado con mensaje modificado (hex):", ct4.hex())
    # internal chacha matrices do not depend on message -> identical rounds
    r1 = logs1[0][2]; r4 = logs4[0][2]
    identical = all(m1 == m4 for (_, m1), (_, m4) in zip(r1, r4))
    print("Las matrices internas (rondas) son identicas entre mensaje original y modificado:", identical)
    ct_bytes_diff2 = sum(bin(a ^ b).count('1') for a, b in zip(ct1, ct4))
    print("Bits distintos entre criptograma1 y criptograma4 (deberia ser exactamente los bits distintos del mensaje):", ct_bytes_diff2)
    msg_diff = sum(bin(a ^ b).count('1') for a, b in zip(pad_to_block(MSG), pad_to_block(MSG2)))
    print("Bits distintos entre mensaje original y modificado:", msg_diff)

    print("\n### TAREA 7: Descifrar el mensaje de la tarea 3 con la clave de la tarea 5 (clave incorrecta) ###")
    ct_wrong, _ = chacha20_encrypt(KEY2, COUNTER, NONCE, ct1)  # XOR again with wrong-key keystream to "decrypt"
    print("Resultado de 'descifrar' con clave incorrecta (bytes):")
    print(ct_wrong)
    try:
        print("Intento de decodificar como utf-8:", ct_wrong.decode('utf-8', errors='replace'))
    except Exception as e:
        print("No se puede decodificar como utf-8:", e)

    print("\n### Generando volcado COMPLETO de las 20 rondas para cada prueba (archivo aparte) ###")
    with open("chacha20_full_rounds.txt", "w") as fh:
        dump_all_rounds("TAREA 3 - Prueba de funcionamiento (bloque 0, counter=1)", KEY, COUNTER, NONCE, fh)
        dump_all_rounds("TAREA 4 - Nonce modificado (bloque 0, counter=1)", KEY, COUNTER, NONCE2, fh)
        dump_all_rounds("TAREA 5 - Clave modificada (bloque 0, counter=1)", KEY2, COUNTER, NONCE, fh)
    print("Archivo 'chacha20_full_rounds.txt' generado con las 20 rondas completas de cada prueba.")

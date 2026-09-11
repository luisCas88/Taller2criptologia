import struct

def bits_from_int(value, nbits):
    return [(value >> (nbits - 1 - i)) & 1 for i in range(nbits)]

def int_from_bits(bits):
    v = 0
    for b in bits:
        v = (v << 1) | b
    return v

class LFSR:
    """LFSR generico de n bits con lista de taps (posiciones que se XOR para el feedback)."""
    def __init__(self, seed_bits, taps):
        self.reg = list(seed_bits)  # reg[0] = bit mas significativo (posicion n-1), ... reg[-1]=bit0
        self.n = len(seed_bits)
        self.taps = taps  # posiciones (0 = LSB) que participan del XOR de feedback

    def _bit_at_pos(self, pos):
        # pos=0 -> LSB -> ultimo elemento de self.reg
        return self.reg[self.n - 1 - pos]

    def step(self):
        # bit de salida = bit menos significativo (posicion 0) actual
        out_bit = self._bit_at_pos(0)
        # feedback = XOR de los bits en las posiciones "taps" (antes del corrimiento)
        fb = 0
        for t in self.taps:
            fb ^= self._bit_at_pos(t)
        # desplazar: se inserta el feedback como nuevo bit mas significativo
        self.reg = self.reg[1:] + [fb]
        return out_bit

    def get_byte(self):
        """Obtiene 8 bits de salida (uno por ciclo) y los arma como entero 0-255 (MSB primero)."""
        bits = [self.step() for _ in range(8)]
        return int_from_bits(bits)


def build_css_registers(key40: bytes):
    assert len(key40) == 5, "la clave debe ser de 40 bits (5 bytes)"
    key_bits = []
    for byte in key40:
        key_bits.extend(bits_from_int(byte, 8))  # 40 bits, MSB primero

    # 16 bits mas significativos -> S1 (17 bits con un 1 fijo como MSB agregado)
    # 24 bits menos significativos -> S2 (25 bits con un 1 fijo como MSB agregado)
    s1_input = key_bits[0:16]
    s2_input = key_bits[16:40]

    s1_seed = [1] + s1_input          # 17 bits
    s2_seed = [1] + s2_input          # 25 bits

    s1 = LFSR(s1_seed, taps=[14, 0])
    s2 = LFSR(s2_seed, taps=[12, 4, 3, 0])
    return s1, s2


def css_keystream(key40: bytes, n_bytes: int):
    s1, s2 = build_css_registers(key40)
    c = 0
    out = bytearray()
    for _ in range(n_bytes):
        x = s1.get_byte()
        y = s2.get_byte()
        total = x + y + c
        z = total % 256
        c = 1 if (x + y) > 255 else 0
        out.append(z)
    return bytes(out)


def css_encrypt(key40: bytes, data: bytes):
    ks = css_keystream(key40, len(data))
    return bytes(a ^ b for a, b in zip(data, ks)), ks


def hamming_bytes(a, b):
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


if __name__ == "__main__":
    KEY = bytes.fromhex("1A2B3C4D5E")
    MSG = ("El algoritmo CSS fue disenado para proteger el contenido de los DVD "
           "mediante un cifrado de flujo basado en registros de desplazamiento. "
           "Aunque su seguridad fue superada, sigue siendo un hito clave en la "
           "historia de la gestion de los derechos digitales.").encode('utf-8')

    print("### Ejercicio 1: cifrado del mensaje de prueba con CSS ###")
    print("Clave (40 bits):", KEY.hex())
    s1, s2 = build_css_registers(KEY)
    print("Semilla S1 (17 bits):", ''.join(map(str, s1.reg)))
    print("Semilla S2 (25 bits):", ''.join(map(str, s2.reg)))

    ct, ks = css_encrypt(KEY, MSG)
    print("Mensaje (utf-8):", MSG)
    print("Longitud mensaje:", len(MSG), "bytes")
    print("KeyStream (hex):", ks.hex())
    print("Criptograma (hex):", ct.hex())

    # verificar que descifra correctamente (CSS es involutivo: XOR con el mismo keystream)
    pt_back, _ = css_encrypt(KEY, ct)
    print("Verificacion (descifrado = mensaje original):", pt_back == MSG)

    print("\n### Ejercicio 2a: Avalancha de CLAVE (cambio de 1 bit) ###")
    KEY2 = bytes.fromhex("1A2B3C4D5F")  # 5E -> 5F difiere en el bit menos significativo
    bitdiff_key = bin(KEY[-1] ^ KEY2[-1]).count('1')
    print(f"Clave original: {KEY.hex()}  Clave modificada: {KEY2.hex()}  (bits distintos entre claves: {bitdiff_key})")
    ct2, ks2 = css_encrypt(KEY2, MSG)
    print("Criptograma con clave modificada (hex):", ct2.hex())
    d_ks = hamming_bytes(ks, ks2)
    d_ct = hamming_bytes(ct, ct2)
    print(f"Bits distintos en el KEYSTREAM: {d_ks} / {len(ks)*8}  ({100*d_ks/(len(ks)*8):.1f}%)")
    print(f"Bits distintos en el CRIPTOGRAMA: {d_ct} / {len(ct)*8}  ({100*d_ct/(len(ct)*8):.1f}%)")

    # evolucion byte a byte (para ver "ronda" = indice de byte donde empieza a divergir fuerte)
    print("Evolucion de diferencia acumulada de bits por byte de keystream (primeros 20 bytes):")
    running = 0
    for i in range(min(20, len(ks))):
        d = bin(ks[i] ^ ks2[i]).count('1')
        running += d
        print(f"  byte {i:3d}: bits distintos={d}  (acumulado={running})")

    print("\n### Ejercicio 2b: Avalancha de MENSAJE (cambio de 1 caracter) ###")
    MSG2 = bytearray(MSG)
    # cambiar 'DVD' por 'DVC' (cambia 1 bit: D(0x44) vs pos)
    idx = MSG.find(b'DVD')
    MSG2[idx+2] = ord('C')  # D=0x44 C=0x43 difiere en 1 bit
    MSG2 = bytes(MSG2)
    bitdiff_msg = bin(MSG[idx+2] ^ MSG2[idx+2]).count('1')
    print(f"Caracter cambiado: '{chr(MSG[idx+2])}' -> '{chr(MSG2[idx+2])}' (bits distintos: {bitdiff_msg})")
    ct3, ks3 = css_encrypt(KEY, MSG2)
    print("Criptograma con mensaje modificado (hex):", ct3.hex())
    print("Keystream identico al original (CSS no depende del mensaje):", ks == ks3)
    d_ct2 = hamming_bytes(ct, ct3)
    print(f"Bits distintos en el CRIPTOGRAMA (deberia ser igual a los bits distintos del mensaje = {bitdiff_msg}): {d_ct2}")

    print("\n### Volcado COMPLETO del KeyStream byte a byte (clave original vs modificada en 1 bit) ###")
    print(f"{'byte':>4} | {'ks orig(hex)':>12} | {'ks mod(hex)':>11} | {'bits dist.':>10} | {'%acum':>6}")
    running = 0
    for i in range(len(ks)):
        d = bin(ks[i] ^ ks2[i]).count('1')
        running += d
        pct = 100 * running / (8 * (i + 1))
        print(f"{i:4d} | {ks[i]:#04x}        | {ks2[i]:#04x}       | {d:10d} | {pct:5.1f}%")

    print("\n### Estado bit a bit de S1 y S2 en los primeros 8 ciclos (clave original) ###")
    s1b, s2b = build_css_registers(KEY)
    for cycle in range(8):
        s1_before = ''.join(map(str, s1b.reg))
        s2_before = ''.join(map(str, s2b.reg))
        x = s1b.get_byte()
        y = s2b.get_byte()
        print(f"ciclo {cycle}: S1_antes={s1_before}  S2_antes={s2_before}  x={x:3d}(0x{x:02x})  y={y:3d}(0x{y:02x})")

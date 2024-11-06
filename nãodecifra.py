S_BOX = [
    [int(x, 16) for x in row.split()] for row in """
63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
""".strip().split("\n")
]

INV_S_BOX = [
    [int(x, 16) for x in row.split()] for row in """
52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb
7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb
54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e
08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25
72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92
6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84
90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06
d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b
3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73
96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e
47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b
fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4
1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f
60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef
a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61
17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d
""".strip().split("\n")
]

R_CON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]


def expandir_chave(chave):
    chave_expandida = [chave[i:i + 4] for i in range(0, len(chave), 4)]

    for i in range(4, 44):
        temp = chave_expandida[i - 1]

        if i % 4 == 0:
            temp = sub_bytes([temp[1:] + temp[:1]])[0]
            rcon_index = (i // 4) - 1

            if rcon_index < len(R_CON):
                temp[0] ^= R_CON[rcon_index]

        chave_expandida.append([a ^ b for a, b in zip(chave_expandida[i - 4], temp)])

    return [chave_expandida[i:i + 4] for i in range(0, len(chave_expandida), 4)]


def sub_bytes(estado):
    for i, row in enumerate(estado):
        for j, byte in enumerate(row):
            if not (0 <= byte <= 255):
                estado[i][j] = 0
    return [[S_BOX[byte >> 4][byte & 0x0F] for byte in row] for row in estado]


def inv_sub_bytes(estado):
    for i, row in enumerate(estado):
        for j, byte in enumerate(row):
            if not (0 <= byte <= 255):
                estado[i][j] = 0
    return [[INV_S_BOX[byte >> 4][byte & 0x0F] for byte in row] for row in estado]


def shift_rows(estado):
    return [estado[0], estado[1][1:] + estado[1][:1], estado[2][2:] + estado[2][:2], estado[3][3:] + estado[3][:3]]


def inv_shift_rows(estado):
    return [estado[0], estado[1][-1:] + estado[1][:-1], estado[2][-2:] + estado[2][:-2],
            estado[3][-3:] + estado[3][:-3]]


def misturar_colunas(estado):
    def misturar_coluna(col):
        a = [byte for byte in col]
        b = [(byte << 1) ^ (0x1b if byte & 0x80 else 0x00) for byte in col]

        return [
            b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1],
            b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2],
            b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3],
            b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0],
        ]

    return [misturar_coluna(col) for col in zip(*estado)]


def inv_misturar_colunas(estado):
    def inv_misturar_coluna(col):
        a = [byte for byte in col]
        return [
            (a[0] * 0x0e) ^ (a[1] * 0x0b) ^ (a[2] * 0x0d) ^ (a[3] * 0x09),
            (a[0] * 0x09) ^ (a[1] * 0x0e) ^ (a[2] * 0x0b) ^ (a[3] * 0x0d),
            (a[0] * 0x0d) ^ (a[1] * 0x09) ^ (a[2] * 0x0e) ^ (a[3] * 0x0b),
            (a[0] * 0x0b) ^ (a[1] * 0x0d) ^ (a[2] * 0x09) ^ (a[3] * 0x0e),
        ]

    return [inv_misturar_coluna(col) for col in zip(*estado)]


def add_round_key(estado, round_chave):
    return [[byte ^ round_chave[i][j] for j, byte in enumerate(row)] for i, row in enumerate(estado)]


def cifrar_bloco(bloco, chave_expandida):
    estado = [list(bloco[i:i + 4]) for i in range(0, 16, 4)]
    estado = add_round_key(estado, chave_expandida[0])

    for round in range(1, 10):
        estado = sub_bytes(estado)
        estado = shift_rows(estado)
        estado = misturar_colunas(estado)
        estado = add_round_key(estado, chave_expandida[round])

    estado = sub_bytes(estado)
    estado = shift_rows(estado)
    estado = add_round_key(estado, chave_expandida[10])

    return bytes(sum(estado, []))


def decifrar_bloco(bloco, chave_expandida):
    estado = [list(bloco[i:i + 4]) for i in range(0, 16, 4)]
    estado = add_round_key(estado, chave_expandida[10])

    for round in range(9, 0, -1):
        estado = inv_shift_rows(estado)
        estado = inv_sub_bytes(estado)
        estado = add_round_key(estado, chave_expandida[round])
        estado = inv_misturar_colunas(estado)

    estado = inv_shift_rows(estado)
    estado = inv_sub_bytes(estado)
    estado = add_round_key(estado, chave_expandida[0])

    return bytes(sum(estado, []))


def applicar_padding(dados):
    padding_length = 16 - (len(dados) % 16)
    return dados + bytes([padding_length] * padding_length)


def remover_padding(dados):
    padding_length = dados[-1]

    if padding_length < 1 or padding_length > 16:
        return dados

    return dados[:-padding_length]


def cifrar(caminho_da_entrada, caminho_da_saida, chave):
    with open(caminho_da_entrada, 'rb') as arquivo_de_entrada:
        dados = arquivo_de_entrada.read()
    dados_com_padding = applicar_padding(dados)
    chave_expandida = expandir_chave(chave)

    with open(caminho_da_saida, 'wb') as arquivo_de_saida:
        for i in range(0, len(dados_com_padding), 16):
            bloco = dados_com_padding[i:i + 16]
            bloco_cifrado = cifrar_bloco(bloco, chave_expandida)
            arquivo_de_saida.write(bloco_cifrado)


def decifrar(caminho_da_entrada, caminho_da_saida, chave):
    with open(caminho_da_entrada, 'rb') as arquivo_de_entrada:
        dados = arquivo_de_entrada.read()

    chave_expandida = expandir_chave(chave)

    with open(caminho_da_saida, 'wb') as arquivo_de_saida:
        for i in range(0, len(dados), 16):
            bloco = dados[i:i + 16]
            bloco_decifrado = decifrar_bloco(bloco, chave_expandida)
            arquivo_de_saida.write(bloco_decifrado)

    with open(caminho_da_saida, 'rb+') as arquivo_de_saida:
        dados_decifrados = arquivo_de_saida.read()
        dados_com_padding = remover_padding(dados_decifrados)
        arquivo_de_saida.seek(0)
        arquivo_de_saida.write(dados_com_padding)
        arquivo_de_saida.truncate()


def main():
    print("Selecione a operação:")
    print("1 - Cifrar")
    print("2 - Decifrar")
    operacao = input("Opção: ")

    caminho_da_entrada = input("Informe o caminho do arquivo: ")
    caminho_da_saida = input("Informe o nome do arquivo de destino: ")
    chave_input = input("Informe a chave (16 bytes, formato decimal separados por vírgula): ")

    chave = bytes(map(int, chave_input.split(',')))

    if len(chave) != 16:
        print("A chave deve ter 16 bytes.")
        return

    if operacao == '1':
        cifrar(caminho_da_entrada, caminho_da_saida, chave)
        print("Arquivo cifrado com sucesso.")

    elif operacao == '2':
        decifrar(caminho_da_entrada, caminho_da_saida, chave)
        print("Arquivo decifrado com sucesso.")

    else:
        print("Operação inválida.")


if __name__ == "__main__":
    main()

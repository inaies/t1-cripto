import time
import os
import sys
import argparse
import base64
import unicodedata
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# --- CONFIGURAÇÃO DE CHAVES GLOBAIS ---
# as chaves de AES são fixas para garantir testes nas mesmas condiçoes

AES_KEY = b"0123456789abcdefghijklmnopqrstuv" # 256-bit key (use 16 for AES-128, 24 for AES-192)

AES_IV = b"1234567890abcdef"   # 128-bit IV for AES

# Chaves Playfair e Rail Fence
PLAYFAIR_KEY1 = "JULIOCEZAR"
RAIL_FENCE_RAILS = 4

# --- FUNÇÕES AUXILIARES DA CIFRA DE PLAYFAIR ---

# Cria a matriz 5x5 do Playfair com a key
def create_key_matrix(key):
    key = key.upper().replace('J', 'I')
    key_letters = []
    for char in key:
        if 'A' <= char <= 'Z' and char not in key_letters:
            key_letters.append(char)

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J é omitido

    # Preparando a lista para popular a matriz no fim
    for char in alphabet:
        if char not in key_letters:
            key_letters.append(char)

    # Monta a matriz final com a lista
    matrix = []
    for i in range(0, 25, 5):  # Aq matriz 5x5
        row = key_letters[i:i+5]  # pega 5 letras de cada vez
        matrix.append(row)        # adiciona como uma linha da matriz
    return matrix

# Prepara e trata o texto para a Playfair
def prepare_playfair_text(text):
    normalized_text = (unicodedata.normalize("NFKD", text) # tira os acentos
                        .encode('ascii', 'ignore')         # tira sinais fora do ascii
                        .decode('ascii'))                  # volta pra string
    
    # monta a string maiuscula com strings de A a Z e substituindo o J por I
    prepared = "".join(filter(str.isalpha, normalized_text.upper().replace('J', 'I')))
 
    pair = []
    i = 0
    while i < len(prepared):
        a = prepared[i]
        # caso seja a ultima letra sem um par
        if i + 1 >= len(prepared):
            pair.append(a + 'X')
            break
        b = prepared[i + 1]
        # letras iguais em sequencia
        if a == b:
            pair.append(a + 'X')
            i += 1
        else:
            pair.append(a + b)
            i += 2
    return pair

# Cria dicionario com cada letra tendo sua linha e coluna -> {char: (row, col)}
# tira o custo de ficar percorrendo a matriz
def build_coord_map(matrix):
    coord_map = {}
    
    for row in range(5):
        for col in range(5):
            char = matrix[row][col]
            coord_map[char] = (row, col)
    
    return coord_map

# Faz a cifra usando as duas matrizes, se a dupla tiver indice par vai para matriz1 e impar matriz2
def playfair_encrypt_dual(pair, matrix1, coord_map1, matrix2, coord_map2):
    result = []

    # Percorre os pares com indice i. (a, b) as duas letras do par
    for i, (a, b) in enumerate(pair):
        if i % 2 == 0:  # pares de indice par usam a matriz 1
            r1, c1 = coord_map1[a]  # consulta o dicionario para cada char
            r2, c2 = coord_map1[b]
            matrix = matrix1
        else:           # pares de indice impar usam a matriz 2
            r1, c1 = coord_map2[a]
            r2, c2 = coord_map2[b]
            matrix = matrix2

        if r1 == r2:  # duas letras do mesmo par na mesma linha
            result.append(matrix[r1][(c1 + 1) % 5])
            result.append(matrix[r2][(c2 + 1) % 5])
        elif c1 == c2: # duas letras do mesmo par na mesma coluna
            result.append(matrix[(r1 + 1) % 5][c1])
            result.append(matrix[(r2 + 1) % 5][c2])
        else:   # Monta o retangulo corretamente na matriz
            result.append(matrix[r1][c2])
            result.append(matrix[r2][c1])
    return "".join(result)

# decifra os com indice par pela matriz1 e indice impar matriz2
def playfair_decrypt_dual(ciphertext, matrix1, coord_map1, matrix2, coord_map2):
    result = []
    i = 0
    pair_index = 0
    while i < len(ciphertext) - 1:
        a = ciphertext[i]
        b = ciphertext[i+1]

        if pair_index % 2 == 0:  # usa chave 1
            r1, c1 = coord_map1[a]
            r2, c2 = coord_map1[b]
            matrix = matrix1
        else:                       # usa chave 2
            r1, c1 = coord_map2[a]
            r2, c2 = coord_map2[b]
            matrix = matrix2

        if r1 == r2:
            result.append(matrix[r1][(c1 - 1) % 5]) # %5 para voltar para o inicio da linha
            result.append(matrix[r2][(c2 - 1) % 5])
        elif c1 == c2:
            result.append(matrix[(r1 - 1) % 5][c1]) # %5 para voltar para o inicio da coluna
            result.append(matrix[(r2 - 1) % 5][c2])
        else:
            result.append(matrix[r1][c2])
            result.append(matrix[r2][c1])

        i += 2   
        pair_index += 1

    return "".join(result).replace("X", "")

# ------------- CIFRA DE RAIL FENCE (TRANSPOSIÇÃO) ------------------

def rail_fence_encrypt(text, rails):
    """Cifra o texto usando a transposição Rail Fence (zig-zag)."""
    if rails == 1 or len(text) <= rails: return text
    
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1 # 1 para baixo, -1 para cima

    for char in text:
        fence[rail].append(char)
        rail += direction
        
        if rail == rails - 1 or rail == 0:
            direction = -direction
            
    # Junta os trilhos
    return "".join("".join(rail) for rail in fence)

def rail_fence_encrypt_reverse(text, rails):
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1  # 1 para baixo, -1 para cima

    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    # Junta os trilhos lendo de trás pra frente
    return ''.join(''.join(reversed(row)) for row in fence)
# Decifra o texto usando a transposição Rail Fence de forma inversa
def rail_fence_decrypt(ciphertext, rails):
    if rails == 1 or len(ciphertext) <= rails: return ciphertext

    # cria a cerca vazia e o mapa de posições
    fence = [['\n'] * len(ciphertext) for _ in range(rails)]
    
    # mapeia a trajetoria do zigzag no grid
    row, col = 0, 0
    direction = 1
    for _ in range(len(ciphertext)):    
        fence[row][col] = '*' # Marcador de posição
        col += 1
        row += direction
        
        if row == rails - 1 or row == 0:
            direction = -direction

    # preenche a cerca com o texto cifrado (lendo linha por linha)
    index = 0
    for r in range(rails):
        for c in range(len(ciphertext)):
            if fence[r][c] == '*':
                fence[r][c] = ciphertext[index]
                index += 1

    # le o texto decifrado seguindo o mesmo caminho do zigzag
    decrypted_text = []
    row, col = 0, 0
    direction = 1
    for _ in range(len(ciphertext)):
        decrypted_text.append(fence[row][col])
        
        col += 1
        row += direction
        
        if row == rails - 1 or row == 0:
            direction = -direction
            
    return "".join(decrypted_text)

def rail_fence_decrypt_reverse(cipher, rails):
    # 1. recriar o padrão zig-zag (mesma lógica da Rail Fence normal)
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    zigzag = [pattern[i % len(pattern)] for i in range(len(cipher))]

    # 2. contar quantos caracteres caem em cada trilho
    counts = [zigzag.count(r) for r in range(rails)]

    # 3. fatiar o texto cifrado em pedaços (um para cada trilho)
    pos = 0
    rails_content = []
    for count in counts:
        part = list(cipher[pos:pos + count])
        # 🔑 como a cifra foi salva invertendo cada trilho,
        # precisamos inverter de novo para restaurar
        rails_content.append(list(reversed(part)))
        pos += count

    # 4. reconstruir o texto original seguindo o caminho zig-zag
    result = []
    rail_indices = [0] * rails
    for r in zigzag:
        result.append(rails_content[r][rail_indices[r]])
        rail_indices[r] += 1

    return ''.join(result)

# --- MAIN EXECUTION ---

parser = argparse.ArgumentParser(description="Cifra e decifra arquivos usando AES ou uma Cifra de Produto (Playfair + Rail Fence) e mede a performance.")
parser.add_argument("filepath", help="Caminho para o arquivo a ser processado")
parser.add_argument("crypto_type", choices=["cripto", "AES"], help="Tipo de criptografia a ser usada (cripto ou AES)")

args = parser.parse_args()

print(f"\n--- INÍCIO DA EXECUÇÃO ({args.crypto_type}) ---")

try:
    # ler o conteúdo do arquivo
    with open(args.filepath, 'rb') as file:
        plaintext_bytes = file.read()
except FileNotFoundError:
    print(f"ERRO: Arquivo não encontrado em {args.filepath}")
    sys.exit(1)


#----------------------------------------------- SEÇÃO AES ---------------------------------------------------------

if args.crypto_type == "AES":
    print("Modo: AES-256 (CBC) | Chave: FIXA (32 bytes) | IV: FIXO (16 bytes)")
    
    # --- Cifrar (Encrypt) ---
    start_time = time.time()
    
    # Adicionar padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext_bytes = encryptor.update(padded_data) + encryptor.finalize()

    end_time = time.time()
    encryption_time = end_time - start_time
    
    # Salvar o texto cifrado (codificado em Base64 para ser legível/seguro)
    ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("utf-8")
    with open("encrypted_aes.bin", 'w') as enc_file:
        enc_file.write(ciphertext_b64)
    
    print(f"ENCRYPT: Tamanho original: {len(plaintext_bytes)} bytes")
    print(f"ENCRYPT: Tempo: {encryption_time:.6f} segundos")
    print("ENCRYPT: Arquivo cifrado salvo em 'encrypted_aes.bin'")

    # --------------------------------- Decifrar (Decrypt) -----------------------------------------------
    start_time = time.time()
    
    # Decodificar de Base64 e bytes
    ciphertext_to_decrypt = base64.b64decode(ciphertext_b64.encode("utf-8"))
    
    # A cifra é reusada, pois AES (em modo CBC) tem a mesma chave/IV para encriptar e desencriptar
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext_to_decrypt) + decryptor.finalize()

    # Remover padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data_bytes = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    end_time = time.time()
    decryption_time = end_time - start_time
    
    # Salvar os dados decifrados
    with open("decrypted_aes.bin", 'wb') as dec_file:
        dec_file.write(decrypted_data_bytes)
        
    print(f"DECRYPT: Tempo: {decryption_time:.6f} segundos")
    print("DECRYPT: Arquivo decifrado salvo em 'decrypted_aes.bin'")

#     CIFRA DE PRODUTO --- Mistura das duas tecnicas

elif args.crypto_type == "cripto":
    print(f"Modo: Playfair (Chave: {PLAYFAIR_KEY1}) + Rail Fence (Trilhos: {RAIL_FENCE_RAILS})")
    
    # 1. Preparação: O Playfair requer texto, não bytes.
    # Decodifica de bytes para string (assumindo UTF-8)
    plaintext_str = plaintext_bytes.decode('utf-8')
    
    # --- Cifrar (Encrypt) ---
    start_time = time.time()
    
    # playfair_key = PLAYFAIR_KEY
    # 1. PLAYFAIR: Substituição (limpa acentos e cria dígrafos)
    matrix1 = create_key_matrix(PLAYFAIR_KEY1)
    coord_map1 = build_coord_map(matrix1)

    # encripta a segunda chave usada na segunda matriz da Cifra de Playfair de Dois Quadrados
    playfair_key2 = rail_fence_encrypt(PLAYFAIR_KEY1, RAIL_FENCE_RAILS)
    matrix2 = create_key_matrix(playfair_key2)
    coord_map2 = build_coord_map(matrix2)

    prepared_digraphs = prepare_playfair_text(plaintext_str)
    first_playfair_ciphertext = playfair_encrypt_dual(
        prepared_digraphs, matrix1, coord_map1, matrix2, coord_map2
    )

    # RAIL FENCE: Transposição (embaralha a ordem do texto)
    first_rail_fence_encrypted = rail_fence_encrypt(first_playfair_ciphertext, RAIL_FENCE_RAILS)

    final_ciphertext_str = rail_fence_encrypt_reverse(first_rail_fence_encrypted, RAIL_FENCE_RAILS)

    end_time = time.time()
    encryption_time = end_time - start_time
    
    # Salvar o texto cifrado (como string, pois a saída é uma sequência de caracteres)
    final_ciphertext_bytes = final_ciphertext_str.encode('utf-8')
    with open("encrypted_cripto.bin", 'wb') as enc_file:
        enc_file.write(final_ciphertext_bytes)
    
    print(f"ENCRYPT: Tamanho original: {len(plaintext_bytes)} bytes")
    print(f"ENCRYPT: Tempo: {encryption_time:.6f} segundos")
    print("ENCRYPT: Arquivo cifrado salvo em 'encrypted_cripto.bin'")

    # ------------------------- Decifrar (Decrypt) --------------------------------
    start_time = time.time()
    
    # RAIL FENCE: Inverso (Primeiro a transposição, pois foi a última a cifrar)
    first_rail_fence_decrypted = rail_fence_decrypt_reverse(final_ciphertext_str, RAIL_FENCE_RAILS)
    rail_fence_decrypted = rail_fence_decrypt(first_rail_fence_decrypted, RAIL_FENCE_RAILS) # Texto cifrado intermediário recuperado
    decrypted_text_raw = playfair_decrypt_dual(
        rail_fence_decrypted, matrix1, coord_map1, matrix2, coord_map2
    )


    # A saída do Playfair ainda está em maiúsculas e sem pontuação.
    # Salvamos o resultado como bytes codificados em UTF-8.
    decrypted_data_bytes = decrypted_text_raw.encode('utf-8')
    
    end_time = time.time()
    decryption_time = end_time - start_time

    # Salvar os dados decifrados
    with open("decrypted_cripto.bin", 'wb') as dec_file:
        dec_file.write(decrypted_data_bytes)
        
    print(f"DECRYPT: Tempo: {decryption_time:.6f} segundos")
    print("DECRYPT: Arquivo decifrado salvo em 'decrypted_cripto.bin'")

print(f"--- FIM DA EXECUÇÃO ({args.crypto_type}) ---\n")

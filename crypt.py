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
# as chaves de AES são fixas para garantir testes nas msm condiçoes

AES_KEY = b"0123456789abcdefghijklmnopqrstuv" # 256-bit key (use 16 for AES-128, 24 for AES-192)

AES_IV = b"1234567890abcdef"   # 128-bit IV for AES

# Chaves Playfair e Rail Fence
PLAYFAIR_KEY = "MONARQUIA"  # Uma key para a matriz 5x5 max 25
RAIL_FENCE_RAILS = 4       # O numero de trilhos para o zig-zag da Rail Fence

# --- FUNÇÕES AUXILIARES DA CIFRA DE PLAYFAIR ---

def create_key_matrix(key):
    """Cria a matriz 5x5 do Playfair a partir da key """
    key = key.upper().replace('J', 'I')
    # Remove duplicatas e caracteres não-alfabéticos
    key_letters = []
    for char in key:
        if 'A' <= char <= 'Z' and char not in key_letters:
            key_letters.append(char)

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" # J é omitido
    for char in alphabet:
        if char not in key_letters:
            key_letters.append(char)

    matrix = []
    for i in range(0, 25, 5):
        matrix.append(key_letters[i:i+5])
    return matrix

def prepare_playfair_text(text):
    """
    Prepara o texto: 
    1. Normaliza para remover acentos (mantendo apenas A-Z).
    2. Remove pontuação e converte J para I.
    3. Cria dígrafos, adicionando 'X' como padding quando necessário.
    """
    # 1. Normalização para lidar com acentos (ex: 'á' -> 'a')
    normalized_text = unicodedata.normalize("NFKD", text).encode('ascii', 'ignore').decode('ascii')
    
    # 2. Normalização (Maiúsculas, J -> I, remover não-alfabéticos)
    prepared = "".join(filter(str.isalpha, normalized_text.upper().replace('J', 'I')))

    # 3. Criação dos Dígrafos (Adiciona 'X' entre letras duplicadas ou no final ímpar)
    digraphs = []
    i = 0
    while i < len(prepared):
        a = prepared[i]
        if i + 1 >= len(prepared):
            # Última letra sozinha, adiciona 'X'
            digraphs.append(a + 'X')
            break
        b = prepared[i+1]
        
        if a == b:
            # Letras duplicadas, adiciona 'X' e avança apenas uma posição
            digraphs.append(a + 'X')
            i += 1
        else:
            # Dígrafo normal
            digraphs.append(a + b)
            i += 2
    return digraphs

def find_coords(matrix, char):
    """Encontra as coordenadas (linha, coluna) de uma letra na matriz."""
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return -1, -1

def playfair_encrypt(prepared_digraphs, matrix):
    """Cifra o texto usando a regra de Playfair."""
    ciphertext = ""
    for a, b in prepared_digraphs:
        r1, c1 = find_coords(matrix, a)
        r2, c2 = find_coords(matrix, b)

        if r1 == r2: # Mesma linha (regra 1)
            new_a = matrix[r1][(c1 + 1) % 5]
            new_b = matrix[r2][(c2 + 1) % 5]
        elif c1 == c2: # Mesma coluna (regra 2)
            new_a = matrix[(r1 + 1) % 5][c1]
            new_b = matrix[(r2 + 1) % 5][c2]
        else: # Retângulo (regra 3)
            new_a = matrix[r1][c2]
            new_b = matrix[r2][c1]
        
        ciphertext += new_a + new_b
    return ciphertext

def playfair_decrypt(ciphertext, matrix):
    """Decifra o texto usando a regra de Playfair de forma inversa."""
    decrypted_text = ""
    i = 0
    while i < len(ciphertext):
        a = ciphertext[i]
        b = ciphertext[i+1]
        
        r1, c1 = find_coords(matrix, a)
        r2, c2 = find_coords(matrix, b)

        if r1 == r2: # Mesma linha (regra 1)
            new_a = matrix[r1][(c1 - 1) % 5]
            new_b = matrix[r2][(c2 - 1) % 5]
        elif c1 == c2: # Mesma coluna (regra 2)
            new_a = matrix[(r1 - 1) % 5][c1]
            new_b = matrix[(r2 - 1) % 5][c2]
        else: # Retângulo (regra 3)
            new_a = matrix[r1][c2]
            new_b = matrix[r2][c1]
        
        decrypted_text += new_a + new_b
        i += 2

    # Remove o X extra que foi adicionado na fase de preparação.
    # IMPORTANTE: Só remove X de padding.
    return decrypted_text.replace('X', '')

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

def rail_fence_decrypt(ciphertext, rails):
    """Decifra o texto usando a transposição Rail Fence de forma inversa."""
    if rails == 1 or len(ciphertext) <= rails: return ciphertext

    # 1. Cria a cerca vazia e o mapa de posições
    fence = [['\n'] * len(ciphertext) for _ in range(rails)]
    
    # 2. Mapeia a trajetória do zig-zag no grid
    row, col = 0, 0
    direction = 1
    for _ in range(len(ciphertext)):
        fence[row][col] = '*' # Marcador de posição
        col += 1
        row += direction
        
        if row == rails - 1 or row == 0:
            direction = -direction

    # 3. Preenche a cerca com o texto cifrado (lendo linha por linha)
    index = 0
    for r in range(rails):
        for c in range(len(ciphertext)):
            if fence[r][c] == '*':
                fence[r][c] = ciphertext[index]
                index += 1

    # 4. Lê o texto decifrado seguindo o mesmo caminho do zig-zag
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


# --- MAIN EXECUTION ---

parser = argparse.ArgumentParser(description="Cifra e decifra arquivos usando AES ou uma Cifra de Produto (Playfair + Rail Fence) e mede a performance.")
parser.add_argument("filepath", help="Caminho para o arquivo a ser processado")
parser.add_argument("crypto_type", choices=["cripto", "AES"], help="Tipo de criptografia a ser usada (cripto ou AES)")

args = parser.parse_args()

print(f"\n--- INÍCIO DA EXECUÇÃO ({args.crypto_type}) ---")

try:
    # Ler o conteúdo do arquivo
    with open(args.filepath, 'rb') as file:
        plaintext_bytes = file.read()
except FileNotFoundError:
    print(f"ERRO: Arquivo não encontrado em {args.filepath}")
    sys.exit(1)


# ====================================================================
#                          SEÇÃO AES
# ====================================================================

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

    # --- Decifrar (Decrypt) ---
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
    print(f"Modo: Playfair (Chave: {PLAYFAIR_KEY}) + Rail Fence (Trilhos: {RAIL_FENCE_RAILS})")
    
    # 1. Preparação: O Playfair requer texto, não bytes.
    # Decodifica de bytes para string (assumindo UTF-8)
    plaintext_str = plaintext_bytes.decode('utf-8')
    
    # --- Cifrar (Encrypt) ---
    start_time = time.time()
    
    # 1. PLAYFAIR: Substituição (limpa acentos e cria dígrafos)
    matrix = create_key_matrix(PLAYFAIR_KEY)
    prepared_digraphs = prepare_playfair_text(plaintext_str)
    playfair_ciphertext = playfair_encrypt(prepared_digraphs, matrix) # Texto cifrado intermediário

    # 2. RAIL FENCE: Transposição (embaralha a ordem do texto)
    final_ciphertext_str = rail_fence_encrypt(playfair_ciphertext, RAIL_FENCE_RAILS)

    end_time = time.time()
    encryption_time = end_time - start_time
    
    # Salvar o texto cifrado (como string, pois a saída é uma sequência de caracteres)
    final_ciphertext_bytes = final_ciphertext_str.encode('utf-8')
    with open("encrypted_cripto.bin", 'wb') as enc_file:
        enc_file.write(final_ciphertext_bytes)
    
    print(f"ENCRYPT: Tamanho original: {len(plaintext_bytes)} bytes")
    print(f"ENCRYPT: Tempo: {encryption_time:.6f} segundos")
    print("ENCRYPT: Arquivo cifrado salvo em 'encrypted_cripto.bin'")

    # --- Decifrar (Decrypt) ---
    start_time = time.time()
    
    # 1. RAIL FENCE: Inverso (Primeiro a transposição, pois foi a última a cifrar)
    rail_fence_decrypted = rail_fence_decrypt(final_ciphertext_str, RAIL_FENCE_RAILS) # Texto cifrado intermediário recuperado

    # 2. PLAYFAIR: Inverso (Recupera o texto plano e remove padding 'X's)
    decrypted_text_raw = playfair_decrypt(rail_fence_decrypted, matrix)
    
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

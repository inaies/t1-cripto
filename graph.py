import numpy as np
import matplotlib.pyplot as plt

arquivos = ["Alice (9KB)", "Bras Cubas (300KB)", "Moby Dick (1.27MB)"]

# Tempos medidos (em segundos)
aes_encrypt_s = [0.016037, 0.005855, 0.007225]
cripto_encrypt_s = [0.001472, 0.076749, 0.208124]
aes_decrypt_s = [0.000052, 0.001969, 0.004019]
cripto_decrypt_s = [0.002723, 0.109649, 0.398867]

# Converter para milissegundos
aes_encrypt = [t * 1000 for t in aes_encrypt_s]
cripto_encrypt = [t * 1000 for t in cripto_encrypt_s]
aes_decrypt = [t * 1000 for t in aes_decrypt_s]
cripto_decrypt = [t * 1000 for t in cripto_decrypt_s]

x = np.arange(len(arquivos))
largura = 0.35

# Encrypt
plt.figure()
plt.bar(x - largura/2, aes_encrypt, largura, label="AES Encrypt")
plt.bar(x + largura/2, cripto_encrypt, largura, label="Cifra Produto Encrypt")
plt.xticks(x, arquivos)
plt.ylabel("Tempo (ms)")
plt.title("Tempo de Criptografia")
plt.legend()
plt.savefig("encrypt_ms.png")

# Decrypt
plt.figure()
plt.bar(x - largura/2, aes_decrypt, largura, label="AES Decrypt")
plt.bar(x + largura/2, cripto_decrypt, largura, label="Cifra Produto Decrypt")
plt.xticks(x, arquivos)
plt.ylabel("Tempo (ms)")
plt.title("Tempo de Descriptografia")
plt.legend()
plt.savefig("decrypt_ms.png")

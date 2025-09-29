import numpy as np
import matplotlib.pyplot as plt

arquivos = ["Alice (9KB)", "Bras Cubas (300KB)", "Moby Dick (1.27MB)"]

aes_encrypt = [6.4, 6.7, 18.9]
cripto_encrypt = [2.2, 107.9, 342.6]
aes_decrypt = [0.08, 1.1, 4.0]
cripto_decrypt = [3.2, 147.2, 452.9]

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

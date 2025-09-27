# Pré-requisitos

Para executar este programa você precisa ter o Python instalado e a biblioteca cryptography.

Instalação da Biblioteca
```bash
pip install cryptography
```

# Configuração do Script
Todas as chaves para os testes de desempenho estão fixas no início do arquivo cipher_comparison.py (ou playfair.py). Isso garante que todas as execuções ocorram nas mesmas condições para uma comparação justa.

AES_KEY -> b"0123456789abcdefghijklmnopqrstuv"  Chave fixa de 32 bytes (256 bits).

AES_IV  -> b"1234567890abcdef" Vetor de Inicialização fixo de 16 bytes.

PLAYFAIR_KEY  > "MONARQUIA"  Palavra-chave usada para gerar a matriz 5x5.

RAIL_FENCE_RAILS  -> 4  Número de "trilhos" para a transposição em zig-zag.

# Como Executar o Código
O script aceita dois argumentos de linha de comando: o caminho para o arquivo de texto e o tipo de criptografia desejado.

## 3.1. Preparação
Crie um arquivo de texto para teste, por exemplo, teste.txt, no mesmo diretório do script.

## 3.2. Execução (Comparação)
Execute o script duas vezes, uma para cada modo de criptografia:

### A. Testar
```bash
python3 crypt.py teste.txt cripto
```


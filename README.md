# Comparação de Criptografia

Este projeto implementa e compara o desempenho de duas técnicas de criptografia:

- **AES-256 (CBC)**: algoritmo moderno, padrão internacional, extremamente seguro e otimizado.
- **Cifra de Produto (Playfair + Rail Fence)**: uma combinação de duas cifras clássicas (substituição + transposição), criada com objetivo didático para demonstrar conceitos fundamentais de criptografia.

# Ideia da Cifra

A proposta foi **combinar duas técnicas clássicas** de criptografia em camadas para aumentar a complexidade:

1. **Playfair Cipher de Dois quadrados (Substituição por dígrafos)**  
   - O texto é normalizado (sem acentos/pontuação, apenas letras maiúsculas A–Z, com `J` convertido em `I`).  
   - O texto é dividido em pares de letras.  
   - Se as letras forem iguais, insere-se um `X` no meio.  
   - Duas matrizes **5x5** são geradas a partir de duas palavras chaves:
      - No nosso caso, a primeira chave é "JULIOCEZAR".
      - A segunda matriz utiliza a mesma chave, entretanto criptografada com railfance de 4 trilhos.
   - Os pares de caracteres de índice par são associados a primeira matriz, que utiliza a chave original "JULIOCEZAR", enquanto os pares de caracteres de indíce ímpar utilizam a segunda matriz, com a chave criptografada. Assim, a substituição dos pares é feita de acordo com as correspondências de cada matriz.
   - Cada par de caracteres é substituído de acordo com as regras da cifra de Playfair (mesma linha, mesma coluna ou retângulo).

2. **Rail Fence Cipher (Transposição em zig-zag)**  
   - O texto resultante do Playfair é escrito em um padrão de "zig-zag" sobre **4 trilhos**.  
   - A leitura é feita trilho a trilho, alterando a ordem original dos caracteres. 
   - Então, a mesma coisa é feita novamente sobre o texto resultante da primeira execução, entretanto, fazendo a leitura trilho a trilho do final para o começo.

No final, temos uma **cifra de produto**:  
 **2x Substituição (Playfair)  + 2x Transposição (Rail Fence)**. 

# Otimização

Para otimizar o processo de criptografia e decriptografia, na execução da cifra de Playfair foi utilizado a estrutura de dados dicionário para facilitar a busca da substituição correspondente na matriz. Ao invés de percorrer a matriz a cada substituição a ser realizada na criptografia, o código apenas verifica a letra correspondente no dicionário pré-construído na função build_coord_map(), que mapeia cada caractere da matriz ao valor da sua linha e coluna.

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

### A. Testar a Cifra de Produto (Substituição + Transposição)
```bash
python3 crypt.py teste.txt cripto
```

### B. Testar a Cifra AES
```bash
python3 playfair.py teste.txt AES
```

# Gráficos Comparativos

## Comparativo na Criptografia
![Criptografia](https://github.com/inaies/t1-cripto/blob/main/encrypt_ms.png)

## Comparativo na Descriptografia
![Descriptografia](https://github.com/inaies/t1-cripto/blob/main/decrypt_ms.png)




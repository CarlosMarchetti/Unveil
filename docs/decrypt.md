# Recuperação de strings

`python -m unveil strings INPUT -o NOVA_PASTA` detecta o formato pelo conteúdo,
sem executar o código alvo. `--offline` exige as dependências ASM já disponíveis
para reconstrução de JARs; sem essa opção o helper pode baixar suas dependências
verificadas do Maven Central.

## JVM

O Unveil reconhece métodos estáticos que retornam String e possuem operações
Cipher.doFinal ou XOR com String.toCharArray. Base64 é opcional. O interpretador
avalia apenas operações determinísticas explicitamente modeladas, com limites
de instruções, recursão e tamanho. Argumentos desconhecidos, efeitos de
inicialização e chamadas não permitidas permanecem sem solução.

Para JARs, a pipeline simplifica constantes, resolve pools e descriptografa
chamadas até atingir ponto fixo ou o limite de iterações. As chamadas recuperadas
são substituídas por constantes String. ASM verifica as classes; classes
rejeitadas são preservadas. Recursos são preservados e metadados de assinatura
invalidada são removidos. A saída não carrega classes alvo no host.

CLASS avulso permite análise e exportação; reconstrução é feita por JAR.

## PE

O scanner atual lê instruções x86/x64 e acompanha escritas constantes e XOR em
buffers com endereçamento direto por RSP/RBP/ESP/EBP. Só exporta sequências
terminadas em NUL, com UTF-8 imprimível e pelo menos um byte alterado por XOR.
Saltos, chamadas, mudanças da stack e escritas desconhecidas encerram o contexto.

Os resultados são **candidatos**, pois a decodificação linear pode interpretar
dados como instruções. O scanner não emula Windows, não executa o EXE e não
resolve automaticamente loops arbitrários, SIMD, dados do heap, chaves externas
ou funções virtualizadas. O orçamento padrão é de 200.000 instruções/10 segundos.

## Arquivos

- `decrypted-strings.txt`: uma string recuperada por linha, escapada como JSON
  para preservar quebras de linha, NUL e caracteres especiais.
- `visible-strings.txt`: strings já legíveis, separadas dos resultados de
  descriptografia. Em JARs, contém constantes da saída reconstruída.
- `strings-report.json`: formato, hash, locais, padrões, contagens e limitações.
- `recovered.jar` e `jvm-report.json`: somente para entradas JAR.

A pasta precisa ser nova. O arquivo de entrada não é sobrescrito e seu hash é
reconferido antes de publicar os resultados. Zero resultados não comprova que
não existam strings protegidas. Nenhum padrão genérico permite garantir a
recuperação de todas as strings de todos os programas.

# Unveil

Unveil é um deobfuscador estático para JARs Java, escrito principalmente em Python. Ele simplifica bytecode sem carregar nem executar classes do JAR analisado.

O projeto foi criado para análise de clientes Java obfuscados e usa um helper Java/ASM apenas para reescrever classes com segurança e verificar o resultado.

## Recursos

- `ConstantDeobf`: reduz expressões numéricas constantes no bytecode, incluindo operações `int`, `long`, `float` e `double`.
- `StringPoolerDeobf`: recupera pools estáticos de strings pela estrutura do `<clinit>` e substitui os acessos por `LDC`.
- `StringDecrypt`: detecta descriptografadores por chamadas a Base64, `Cipher`, `MessageDigest` e `SecretKeySpec`; avalia somente uma lista limitada de operações determinísticas.
- Pipeline iterativa até ponto fixo.
- Preservação de recursos do JAR e das classes que não puderem ser transformadas com segurança.
- Validação de classes modificadas com ASM antes de publicar o JAR de saída.
- Relatório JSON com transformações, descriptografias, erros e itens não resolvidos.

## Segurança

O JAR alvo não é executado, carregado por `Class.forName`, nem colocado no classpath do helper. O interpretador estático não permite chamadas arbitrárias, `Runtime.exec`, `ProcessBuilder`, rede, JNI ou reflexão do alvo.

Caso uma transformação ou validação falhe, a classe original é preservada e o processo continua com as demais classes.

## Requisitos

- Python 3.10 ou superior
- JDK 8 ou superior, com `java` e `javac` disponíveis no `PATH`

Instale as dependências Python:

```powershell
python -m pip install -r requirements.txt
```

Na primeira execução, o Unveil baixa as dependências ASM necessárias ao helper e confere os hashes publicados pelo Maven Central. Depois disso, use `--offline` para impedir downloads.

## Uso

```powershell
python main.py input.jar output.jar
```

Exemplo com relatório explícito:

```powershell
python main.py client.jar client-deobf.jar --report deobf-report.json
```

Outras opções:

```powershell
python main.py input.jar output.jar --max-iterations 20
python main.py input.jar output.jar --offline
```

Sem argumentos, o programa usa os caminhos padrão definidos em `main.py`. Para compartilhar ou automatizar a ferramenta, prefira sempre passar input e output na linha de comando.

## Como funciona

```text
ConstantDeobf → StringPoolerDeobf → StringDecrypt → repetir até não haver alterações
```

O leitor Python extrai instruções, campos e constantes sem modificar classes. As alterações são enviadas ao helper em um plano binário restrito. O helper aplica somente substituições aprovadas, preserva frames existentes, recalcula limites de stack/locals e usa as verificações do ASM. Classes rejeitadas nunca entram no JAR de saída.

`StringDecrypt` suporta, quando a transformação for totalmente determinística, Base64, digests MD2/MD5/SHA, `Arrays.copyOf`, chaves, IVs e DES, DESede, AES ou Blowfish nos modos ECB/CBC. O algoritmo é obtido das constantes resolvidas no bytecode; não há suposição fixa de DES ou AES.

## Relatório

O relatório contém, entre outros:

```json
{
  "constants": {},
  "stringPools": {},
  "decryptors": [],
  "decryptedStrings": [],
  "unresolved": [],
  "errors": []
}
```

Cada string recuperada registra classe, método, offset de bytecode, decryptor, ciphertext e plaintext. Chaves não são incluídas no relatório.

## Testes

```powershell
python -m unittest discover -s tests -v
python tests/integration.py
```

Os testes criam um JAR sintético próprio e verificam a saída com `java -Xverify:all`. Eles cobrem aritmética JVM, pools renomeados, AES, DES, Blowfish, CBC com IV, Base64/XOR, preservação de recursos e rejeição de planos inválidos.

## Recuperação de nomes

O próximo estágio planejado é `NameRecovery`, voltado inicialmente a Minecraft 1.5.2:

1. Aplicar mappings conhecidos à base do Minecraft e às bibliotecas identificadas.
2. Usar ferramentas de correspondência estrutural, como [CLModding Matcher](https://github.com/CLModding/Matcher), para transferir nomes de classes, campos e métodos equivalentes.
3. Analisar as classes exclusivas do client por relações de chamadas, tipos, herança, recursos e strings já recuperadas.
4. Gerar nomes inferidos com nível de confiança e evidências, mantendo separado o que foi recuperado por mapping do que foi nomeado semanticamente.

Nomes originais que foram removidos pelo obfuscador não podem ser provados apenas pelo bytecode. Para classes próprias, o objetivo do estágio será produzir nomes coerentes e revisáveis, não alegar uma recuperação exata sem uma referência externa.

## Estrutura

```text
main.py                 CLI e pipeline
deobf/                  parser, interpretador, passes e writer
helper/                 helper Java/ASM e pom.xml
tests/                  testes unitários e integração
requirements.txt        dependências Python
```

## Licença

Ainda não foi definida.

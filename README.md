# Unveil

Unveil é um framework modular de análise estática e desofuscação para JVM e binários PE, escrito principalmente em Python. Ele inspeciona JAR/CLASS e EXE/DLL e simplifica bytecode sem executar o alvo.

O projeto foi criado para análise de clientes Java obfuscados e usa um helper Java/ASM apenas para reescrever classes com segurança e verificar o resultado.

## Interface gráfica para patches

Abra `Abrir-Unveil-GUI.cmd` ou execute `python -m unveil.gui`. O desktop
Workbench reúne análise JVM/PE, recuperação de strings com exportação TXT/JAR,
busca de strings/bytes em PEs e dumps,
editor de patches por formulários e exportação de aplicadores PowerShell
para Windows e testes offline no Windows Sandbox. Veja o [guia da GUI](docs/gui.md)
para uso, requisitos e limites da edição no-code.

## Framework 0.2

```powershell
python -m unveil strings input.jar -o recovered-strings --offline
python -m unveil strings input.exe -o recovered-native
```

O comando exporta `decrypted-strings.txt`, `visible-strings.txt` e um relatório
com evidências e casos não resolvidos. Para JAR, produz também `recovered.jar`
com substituições verificadas por ASM. Padrões JVM incluem criptografia
determinística e XOR; PEs possuem reconhecimento inicial de XOR constante em
buffers na stack. A cobertura é limitada aos padrões suportados: nenhuma
recuperação completa de todas as strings de qualquer proteção é prometida.

O [documento original](docs/Unveil_Project.md) orienta a evolução. O Core, o módulo JVM e o worker Native possuem responsabilidades separadas. Veja a [arquitetura](docs/architecture.md) e o [estado de cada entregável](docs/implementation-status.md), incluindo as diferenças em relação à proposta Java/C++.

```powershell
python -m unveil inspect sample.jar
python -m unveil analyze sample.jar --format json -o analysis.json
python -m unveil plan sample.jar --format html -o plan.html
python -m unveil deobfuscate sample.jar -o clean.jar --transform constant --offline
python -m unveil deobfuscate sample.jar -o clean.jar --offline
python -m unveil verify clean.jar --offline
python -m unveil native inspect sample.exe
python -m unveil native imports sample.dll --format json
python -m unveil diff sample.jar clean.jar --format json
```

`inspect`, `analyze`, `plan` e `verify` também aceitam CLASS individual. A reescrita requer JAR. O [Native](docs/native.md) lê PE32/PE32+, imports, exports, TLS, strings, entropia e overlay em um processo separado. ELF e disassembly ainda não estão implementados.

Os novos comandos produzem [relatórios versionados](docs/pipeline.md) com evidências, confiança, diagnósticos e alterações antes/depois. Texto e HTML são renderizações do JSON canônico. `analyze` e `plan` não precisam do helper Java nem fazem downloads.

## Recursos

- Detecção heurística de VMProtect e [unpacker em desenvolvimento](docs/unpacker.md): emulação limitada, dump de processo Windows por `--dump` e lançamento explícito por `--dump --launch`. Ainda não remove VMProtect nem devirtualiza automaticamente.

- `ConstantDeobf`: reduz expressões numéricas constantes no bytecode, incluindo operações `int`, `long`, `float` e `double`.
- `StringPoolerDeobf`: recupera pools estáticos de strings pela estrutura do `<clinit>` e substitui os acessos por `LDC`.
- `StringDecrypt`: detecta descriptografadores por chamadas a Base64, `Cipher`, `MessageDigest` e `SecretKeySpec`; avalia somente uma lista limitada de operações determinísticas.
- `NameRecovery`: compara referências, importa mappings, sugere nomes com evidências e aplica renomeações de classes, métodos e campos.
- Pipeline iterativa até ponto fixo.
- Preservação de recursos do JAR e das classes que não puderem ser transformadas com segurança.
- Validação de todas as classes da saída com ASM antes de publicar o JAR; falhas ficam registradas.
- Relatório JSON com transformações, descriptografias, erros e itens não resolvidos.

## Segurança

O JAR alvo não é executado, carregado por `Class.forName`, nem colocado no classpath do helper. O interpretador estático não permite chamadas arbitrárias, `Runtime.exec`, `ProcessBuilder`, rede, JNI ou reflexão do alvo.

Nos passes de simplificação, uma classe rejeitada é preservada. No NameRecovery, a aplicação é atômica: qualquer falha de reescrita ou validação cancela a publicação inteira, evitando referências parcialmente renomeadas.

Antes de descompactar entradas, os fluxos de desofuscação e NameRecovery validam o JAR inteiro, incluindo recursos: no máximo 100.000 entradas, 256 MiB por entrada e 512 MiB de tamanho descompactado total declarado. Nomes duplicados e entradas ZIP criptografadas são rejeitados. O NameRecovery mantém também seu limite de 64 MiB por classe. Esses limites não representam um teto de memória do processo; os modelos de análise consomem memória adicional.

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

A entrada é obrigatória. Na CLI legada, omitir a saída gera `nome-da-entrada-deobf.jar` ao lado da entrada. Os caminhos pessoais predefinidos foram removidos.

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

Para os testes de contrato JSON e lint, instale `requirements-dev.txt`. Em um checkout novo, prepare o helper antes das integrações:

```powershell
python -m pip install -r requirements-dev.txt
python -c "from deobf.writer import build; build()"
```

```powershell
python -m unittest discover -s tests -v
python tests/integration.py
python tests/names_integration.py
python tests/framework_integration.py
```

Os testes criam um JAR sintético próprio e verificam a saída com `java -Xverify:all`. Eles cobrem aritmética JVM, pools renomeados, AES, DES, Blowfish, CBC com IV, Base64/XOR, preservação de recursos e rejeição de planos inválidos.

## Recuperação de nomes

O `NameRecovery` trabalha sobre um JAR já simplificado. Para Minecraft 1.5.2, forneça um JAR de referência dessa versão e mappings correspondentes ao namespace dele. Os arquivos de referência não são distribuídos no projeto.

```powershell
python main.py client.jar client-deobf.jar
python main.py client-deobf.jar --recover-names --reference minecraft-1.5.2.jar --reference-mappings client.srg --mcp-dir conf --names-dir names
python main.py client-deobf.jar client-named.jar --apply-mappings names/approved-mappings.json --names-dir names-applied
```

O diretório `conf` deve conter os CSVs MCP `methods.csv` e `fields.csv`. Sem esses CSVs, os nomes SRG são mantidos. Também são aceitos Tiny v1/v2 e JSON. Mappings já correspondentes ao client podem ser importados com `--seed-mappings`; para resultados do Matcher, exporte mappings Tiny, em vez de fornecer uma sessão `.match`.

Sem referência, gere sugestões semânticas locais:

```powershell
python main.py client-deobf.jar --recover-names --names-dir names
```

Revise `names/mappings.json`, marque as propostas desejadas com `"approved": true` e aplique esse arquivo. `--accept-inferred` permite considerar automaticamente sugestões semânticas de confiança alta, ainda sujeitas às verificações de segurança. Um output junto de `--recover-names` analisa e aplica o subconjunto aprovado em uma única execução.

Os relatórios distinguem correspondências estruturais, mappings importados e nomes inferidos. Nomes originais apagados pelo obfuscador não podem ser provados somente pelo bytecode. As sugestões para código próprio são baseadas em regras locais; não usam serviços de IA ou rede.

Veja [o guia do NameRecovery](docs/NameRecovery.md) para formatos, validação e limites.

## Estrutura

```text
main.py                 CLI legada e encaminhamento de comandos
unveil/cli.py           CLI unificada
unveil/core/            artefatos, contratos, registro e relatórios
unveil/jvm/             análise, plano e pipeline JVM reutilizável
unveil/native/          worker de análise PE
deobf/                  parser, interpretador, passes e writer
deobf/names/            comparação, mappings, segurança e aplicação
helper/                 helper Java/ASM e pom.xml
docs/NameRecovery.md    guia de recuperação de nomes
tests/                  testes unitários e integração
requirements.txt        dependências Python
```

## Licença

Ainda não foi definida.

# Pipeline e relatórios

## Comandos

```powershell
python -m unveil inspect sample.jar
python -m unveil analyze sample.jar --format json -o analysis.json
python -m unveil plan sample.jar --format html -o plan.html
python -m unveil deobfuscate sample.jar -o clean.jar --offline
python -m unveil deobfuscate sample.jar -o constants.jar --transform constant --offline
python -m unveil verify clean.jar --offline --format json
python -m unveil diff sample.jar clean.jar --format json
python -m unveil native inspect sample.exe
python -m unveil native imports sample.dll --format json
python -m unveil native strings sample.exe --format json
```

Os mesmos subcomandos estão disponíveis por `python main.py`. A CLI legada `python main.py input.jar output.jar` continua disponível. Sem entrada, a CLI agora apresenta erro de uso; não utiliza caminhos pessoais predefinidos.

`inspect` lê metadados. `analyze` acrescenta detecção e evidências. `plan` expõe os locais resolvíveis no estado atual, sem carregar o helper ou modificar a entrada. `deobfuscate` faz análise inicial, aplica passes selecionados até ponto fixo, verifica todas as classes da saída e publica um novo JAR e um relatório canônico. A limpeza de metadados sintaticamente inválidos permanece uma etapa comum, mesmo com apenas um transform selecionado.

O plano inicial não é um arquivo executável de patches: os passes são reavaliados após cada alteração. Novas constantes ou strings podem aparecer nas iterações seguintes. Os limites e pressupostos de cada pass continuam valendo; consulte também o README e os campos `limitations` dos relatórios.

## Modelo de relatório

`docs/report.schema.json` descreve o envelope canônico v1. O relatório contém `schemaVersion`, `tool`, `input`, `mode`, `status`, `metadata`, `findings`, `diagnostics`, `transformations` e `output`. Análises não possuem artefato de saída (`output: null`). Texto e HTML são renderizações desse mesmo objeto.

Findings separam severidade de confiança. As pontuações são heurísticas explicadas por evidências; não são probabilidades calibradas. Expressões constantes também existem em programas não ofuscados. A presença de uma seção RWX ou com alta entropia não prova packing ou comportamento malicioso.

Cada alteração JVM inclui classe, método, descriptor, iteração, offset, instruções anteriores e substituição. Os offsets descrevem a classe no início do pass daquela iteração. `candidates` conta tentativas de aplicação; `changed` conta substituições presentes na saída, `failed` conta rejeições do writer e `skipped` inclui alterações descartadas por rollback. `initialCandidates` corresponde ao plano inicial. O relatório conserva `legacyDetails` para diagnóstico e compatibilidade com os contadores existentes.

O JAR é gravado em arquivo temporário, reaberto e conferido antes de substituir o destino. O relatório também é publicado por substituição atômica individual. **O par JAR/relatório não é uma transação única:** uma falha de disco ao publicar o relatório pode deixar o JAR pronto sem seu relatório. O comando retorna falha nesse caso.

## Verificação e códigos de saída

- `0`: operação concluída.
- `1`: erro de uso/execução ou verificação reprovada (`argparse` usa `2` para sintaxe inválida).
- `2`: análise parcial, erros preservados ou itens não resolvidos.
- `2` também indica `blocked` no protótipo de unpacking (backend indisponível, opt-in ausente ou dependência não modelada).

Logs do helper vão para stderr. Com `--format json`, stdout contém apenas JSON; `-o` grava também o relatório no caminho escolhido. A desofuscação gera por padrão `nome-da-saida.report.json`.

`verify` JVM usa ASM sem carregar classes alvo. `verify` PE significa inspeção estrutural, não execução nem validação de confiança Authenticode. `diff` compara hashes e metadados estruturais; ainda não produz diff por instrução.

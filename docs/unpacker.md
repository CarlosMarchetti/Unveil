# Unpacker experimental

## Estado real

O projeto possui detecção automática de indícios de VMProtect, emulação experimental de CPU AMD64 e captura real do módulo principal de um processo Windows mediante `--dump`. A integração externa com VMPDump permanece disponível para reconstrução de imports. **Ainda não possui remoção automática comprovada de VMProtect nem devirtualização.**

O backend pode capturar uma imagem mapeada quando o código emulado começa a executar bytes escritos em uma seção executável originalmente sem conteúdo físico. Essa condição é uma pista de transição, não prova de OEP, unpacking completo ou equivalência semântica. Por isso o relatório permanece `partial`, com `unpacked: false`, `devirtualized: false` e `output.verified: false`.

## Uso

Sem emulação: identifica o protetor e descreve as etapas possíveis.

```powershell
python -m unveil plan input.exe --format json -o plan.json
python -m unveil unpack input.exe --report unpack-plan.json
```

Instale as dependências opcionais antes de usar o backend:

```powershell
python -m pip install -r requirements-unpack.txt
python -m unveil unpack input.exe --emulate -o candidate.mapped.bin --report probe.json
```

O nome de saída precisa terminar em `.bin`, pois representa memória organizada por RVA, e não um PE reconstruído. Uma tentativa sem captura não altera um arquivo de saída já existente. `--report` grava o relatório JSON, texto ou HTML segundo `--format`. Os logs não contaminam o JSON em stdout.

`unpack` sem `--emulate`, `--dump` ou `--import-fix` faz apenas detecção e planejamento. `--emulate` permite emular instruções em Unicorn, em processo filho, sem iniciar o executável como processo Windows. Nessa modalidade não existe encaminhamento de syscalls ou APIs do alvo para o host. Isso não constitui uma sandbox de sistema operacional e depende da integridade do parser/emulador.

## Captura de um processo Windows real

Para capturar um programa já iniciado, informe o PID e o mesmo arquivo EXE usado por esse processo:

```powershell
python -m unveil unpack "C:\caminho\programa.exe" --dump --pid 1234 -o "capture.mapped.bin"
```

O nome também pode ser resolvido por `--process-name programa.exe`. Se mais de um processo corresponder, o comando pede um PID explícito. Essa opção requer `psutil`; a seleção por PID e o lançamento não dependem dessa biblioteca.

Para **executar conscientemente o EXE pelo próprio Unveil** e depois capturar seu módulo principal:

```powershell
python -m unveil unpack "C:\analysis\input.exe" --dump --launch --wait-seconds 10 -o "C:\analysis\live.mapped.bin"
```

`--launch` exige `--dump`. O programa é iniciado no Windows com as permissões do usuário e seu diretório como diretório de trabalho. Ele pode mostrar sua interface, acessar rede e alterar arquivos como em uma execução normal. A confirmação operacional é o próprio comando com essas duas opções; não há execução implícita durante `inspect`, `plan` ou `--emulate`.

O alvo **permanece aberto depois da captura**. O relatório registra seu PID e se ainda estava rodando. O Unveil não encerra automaticamente um programa do usuário, inclusive quando a captura falha. Argumentos adicionais podem ser passados com `--target-arg=VALOR`, repetidamente.

`--wait-seconds` aceita 0..60 e controla apenas uma espera fixa. Dez segundos não comprovam descompactação nem chegada ao OEP. Para uma aplicação que exige interação, abra-a e use o modo `--pid` quando atingir o estado desejado.

A captura usa `OpenProcess` com permissões de consulta/leitura, identifica o módulo principal pelo caminho do EXE, considera a base efetiva com ASLR e lê suas páginas com `ReadProcessMemory`. Não injeta código, não altera permissões das páginas e não solicita privilégios de depuração. Páginas guard, inacessíveis ou não comprometidas são preservadas como lacunas explícitas no relatório e preenchidas com zero no arquivo.

O limite de imagem é 128 MiB, com orçamento de leitura ajustável por `--dump-timeout` de 1..120 segundos. O processo não é suspenso: a captura não é uma fotografia atômica de todas as páginas. Por padrão, junto de `live.mapped.bin` é gravado `live.mapped.dump.json`. Uma falha antes da publicação preserva o dump anterior. Os dois arquivos são publicados individualmente, sem transação conjunta.

Capturar bytes com sucesso resulta em `status: partial` e `output.verified: false`. Além do `.bin` original, o comando agora gera automaticamente `.analysis.exe` e `.analysis.recovery.json`. O PE de análise recebe offsets físicos e tamanhos para as seções materializadas, usa a base efetiva de captura e passa por comparação byte a byte das seções via leitura PE. O relatório separado contém candidatos a strings ASCII/UTF-16LE por seção, RVA, VA e offset no PE reconstruído. Há um limite de 5.000 candidatos por seção e encoding, com contagem total para indicar truncamento.

Esse arquivo serve para análise estática: **não é um executável desprotegido e validado**. Os imports, OEP, relocations e unwind não são reconstruídos. Os bytes virtualizados permanecem. Strings impressas não equivalem a strings decriptadas; conteúdo do heap não está no dump do módulo. O relatório principal distingue os metadados do arquivo original dos artefatos recuperados.

É possível aproveitar um dump já salvo, sem iniciar o programa outra vez. Informe a base efetiva registrada em `unpacking.imageBase` no relatório daquela captura:

```powershell
python -m unveil.native.recovery "C:\analysis\live.mapped.bin" --image-base 0x7ff60d1d0000 -o "C:\analysis\input.analysis.exe"
```

A base acima pertence à captura estudada; outras execuções podem ter outra base por ASLR. A reconstrução segue os campos de seção da [especificação PE da Microsoft](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). Diretórios de certificado, debug e bound imports com referências antigas são removidos do PE derivado; o dump original permanece intacto. Não execute o arquivo de análise como se fosse o programa original.

O backend Windows foi validado sobre o próprio módulo do interpretador e sobre um processo Python iniciado com código de teste do projeto. Esses testes não comprovam a remoção da proteção de um aplicativo protegido.

## Detecção por evidências

O detector combina o par `.vmp0`/`.vmp1` com evidências como seções sem conteúdo físico, entropia de regiões executáveis, stub `PUSH imm32; CALL/JMP rel32` e imports de resolução dinâmica. Nomes isolados não bastam. A regra é deliberadamente conservadora: seções renomeadas e variantes diferentes podem não ser reconhecidas; amostras artificiais podem reproduzir os sinais e gerar falso positivo.

A saída é `suspected`, nunca certeza. A pontuação é heurística, não probabilidade calibrada. `version` permanece `null`: o algoritmo de import-position hash do DiE ainda não foi reproduzido. A versão informada pelo usuário não é inserida como se fosse resultado automático.

## Backend de observação

- PE32+ AMD64, imagem de até 128 MiB e stack emulada de 2 MiB.
- Padrão: até 100.000 instruções e 5 segundos; máximos: 10.000.000 e 60 segundos.
- Timeout adicional no processo pai para encerrar um worker que não responda.
- Por padrão, somente a entrada e arquivos temporários controlados pelo Unveil são usados. `--module-dir` habilita leitura de DLLs em raízes explícitas para mapeamento na memória do Unicorn, sem carregá-las no processo nativo do host.
- Imports são substituídos por endereços sentinela. `KERNEL32/KERNELBASE!LocalAlloc` recebe um modelo limitado a memória fixa, tamanho positivo e flags 0/0x40. A memória existe somente no emulador; o orçamento acumulado é 64 MiB, arredondado por página. Argumentos não suportados bloqueiam com diagnóstico. Sem `--module-dir`, os demais imports interrompem a emulação. O modelo segue o subconjunto documentado de [LocalAlloc](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localalloc).
- Syscalls, instruções de I/O e fontes conhecidas de estado externo como CPUID/RDTSC são interrompidas por padrão. `--emulate --model-tsc` permite simular somente RDTSC como `instruções executadas * 100`, sem consultar a CPU do host. O relatório registra leituras e `realTiming: false`; caminhos que dependem de tempo permanecem hipotéticos. RDTSCP continua bloqueado.
- O backend inicializa TLS estático de um único módulo AMD64 sem callbacks: copia o template, reserva zero-fill, atribui índice zero e disponibiliza o vetor TLS e o campo Self de um TEB mínimo por GS. A alocação TLS é limitada a 1 MiB. Callbacks não vazios bloqueiam antes da execução; endereços e tamanhos inválidos são rejeitados.
- O backend modela campos selecionados do TEB/PEB AMD64: Self, limites da stack, vetor TLS, ponteiro para PEB, ImageBase, BeingDebugged e Ldr. As três listas Ldr são duplamente ligadas e atualizadas quando módulos são mapeados, com nomes Unicode, bases e tamanhos. Leituras de campos desconhecidos interrompem a execução como `unmodeled_environment_field`, sem aceitar zeros como estado válido. Os layouts seguem o [TEB da Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb) e as [definições PEB/LDR do Wine](https://github.com/wine-mirror/wine/blob/master/include/winternl.h).
- `--windows-version MAJOR.MINOR.BUILD` fornece um perfil explícito para os campos de versão do PEB; a opção exige `--emulate`. Sem perfil, consultas desses campos são bloqueadas. `--debugged` define BeingDebugged no processo emulado. O relatório distingue esse perfil de estado capturado de um processo real.
- `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `GetCurrentProcess` e `GetCurrentThread` consultam o estado do guest. `NtQueryInformationProcess`/`ZwQueryInformationProcess` suportam apenas o pseudo-handle do processo atual e as classes 7/30 (debug port/debug object). A classe 30 retorna `STATUS_PORT_NOT_SET` quando não há debugger; handles de debug object para um guest debugado não são implementados. O quinto argumento é lido da stack conforme a convenção Win64. `NtSetInformationThread`/`ZwSetInformationThread` suportam somente classe 17 no pseudo-handle da thread atual, registrando o estado ThreadHideFromDebugger; comprimento diferente de zero retorna `STATUS_INFO_LENGTH_MISMATCH`. Esses modelos não executam syscalls no host. Referências: [NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess) e [implementação ThreadHideFromDebugger do ReactOS](https://reactos.org/pipermail/ros-diffs/2018-February/067080.html).
- O backend não implementa loader Windows completo, exceções ou criação de threads. Páginas de imagem são mapeadas RWX para observar escrita; isso difere das permissões reais do Windows. A decodificação usa um cache limitado a 65.536 instruções, invalidado por escritas em páginas de código, inclusive quando uma instrução cruza páginas; código modificado continua sendo verificado.

O teste sintético grava uma instrução em uma seção originalmente vazia e transfere o controle para ela. Ele demonstra a captura pelo backend, **não compatibilidade com VMProtect comercial**. Outros testes cobrem limites, memória não mapeada, syscall, ausência de opt-in e preservação de arquivos.

## Módulos no emulador

`--emulate --module-dir DIRETORIO` habilita `GetModuleHandleA/W`, `LoadLibraryA/W` e `GetProcAddress` dentro da memória emulada. Até oito raízes existentes podem ser fornecidas repetindo a opção. Não existe busca implícita no PATH, no diretório do alvo ou na instalação do Windows. Nomes solicitados precisam ser basenames de DLL; caminhos absolutos, traversal e links que escapem da raiz são rejeitados. Um arquivo ausente ou inválido produz diagnóstico e bloqueia a tentativa; não é substituído por uma DLL falsa.

O loader suporta DLLs AMD64 PE32+, seções físicas e zero-fill, relocations DIR64, exports por nome (sensíveis a maiúsculas) e ordinal, além de forwarders por nome/ordinal entre DLLs. A resolução de forwarders tem limite de 16 etapas e detecta ciclos. O formato segue a [especificação PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table) e o contrato de [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).

`GetModuleHandle(NULL)` retorna a base do EXE; consultas ao basename original também funcionam quando o worker usa uma cópia temporária. Exports do EXE são indexados. Imports normais do EXE e dos módulos materializados representam dependências de startup, mapeadas sob demanda durante consultas. `GetModuleHandle` retorna zero para módulos não declarados/carregados; `LoadLibrary` permite mapear uma DLL disponível nas raízes. Repetir um carregamento reutiliza sua base.

As tabelas de imports normais e delay imports baseados em RVA são validadas e recebem sentinelas identificadas por DLL/símbolo. Na chamada, dependências e exports são resolvidos sob demanda. Funções puras de DLLs próprias sem inicialização podem ser executadas pelo Unicorn. O loader não executa DllMain ou callbacks TLS; código não modelado de DLLs com entry point ou TLS é bloqueado como `module_initialization_not_modeled`. Portanto isso não equivale à inicialização completa de módulos pelo Windows. Contratos API-set ainda precisam ser fornecidos como DLLs nas raízes; não há mapa de API-set do sistema.

Limites: 64 DLLs, 128 MiB por arquivo/imagem, 256 MiB de memória mapeada acumulada para DLLs, 65.536 imports/exports por módulo e 65.536 consultas de exports por tentativa. Os relatórios registram caminhos, SHA256, bases, contagens, relocations, dependências e até 256 consultas de módulos/exports, com indicação de truncamento. Os bytes das DLLs de análise pertencem à instalação ou às fixtures fornecidas, não ao processo capturado de um aplicativo protegido.

A integração com VMPDump pode operar separadamente por `--import-fix` ou depois da captura com `--dump --import-fix --vmpdump-path CAMINHO`. Nesse último caso reutiliza o PID da captura, inclusive quando iniciado com `--launch`. Exige um backend existente antes de iniciar o alvo. O VMPDump grava seu PE ao lado do módulo original; o Unveil recusa a operação se esse arquivo já existir para preservar evidências e impedir falsos sucessos com arquivos antigos.

O adaptador verifica o layout físico, a arquitetura e os imports do arquivo produzido e compara os símbolos com o original. Ausência de imports adicionais é explicitamente informada. Mesmo com imports adicionais, o resultado permanece parcial: essa comparação não demonstra que todas as chamadas foram corrigidas nem que o programa funciona. Não substitui a devirtualização. [VMPDump](https://github.com/0xnobody/vmpdump). A emulação usa as primitivas de CPU e memória do [Unicorn](https://www.unicorn-engine.org/docs/tutorial.html).

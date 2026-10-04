# Acompanhamento da proposta

Referência preservada em [Unveil_Project.md](Unveil_Project.md). Esta implementação cobre o núcleo funcional do primeiro ciclo; não declara concluídas todas as fases 0–6.

| Item da proposta | Situação |
|---|---|
| Core, artefatos, contexto, findings e diagnósticos | Implementado em Python |
| Contratos e ordenação de componentes | Implementado; registro explícito interno |
| JVM reutilizável | Pipeline extraído da CLI; passes existentes preservados |
| JAR/CLASS e índice de classes/métodos | Implementado; reescrita de CLASS individual pendente |
| Três transforms, isolados ou combinados | Implementado com seleção pela CLI |
| Analyze/plan antes de modificar | Implementado |
| Relatório v1, evidências e alterações | Implementado; JSON/texto/HTML |
| Verificação e preservação da entrada | Implementado; sem prova completa de linkage |
| PE headers/seções/imports/exports/TLS/overlay | Implementado com pefile, worker separado |
| Strings e entropia PE | Implementado com limites documentados |
| GUI JVM/PE e patches Windows | Tkinter; análise, exportação de strings, editor AMD64 e pacotes offline Sandbox |
| TXT e JAR com strings recuperadas | Comando `strings`; padrões determinísticos JVM e candidatos XOR na stack de PEs |
| Testes e CI | Unitários e integrações com fixtures próprias |
| Licença | Pendente decisão do titular; recomendação do documento: Apache-2.0 |
| Engines Java 17/C++20 e build Gradle/CMake | Pendente; decisão incremental documentada |
| Plugins externos, manifest, SDK distribuível | Pendente; protocolos internos disponíveis |
| JVM CFG/call graph, native disassembly/CFG | Fase posterior |
| Detecção VMProtect e emulação limitada | Protótipo opt-in com captura candidata; não remove a proteção |
| Módulos PE no emulador | AMD64, relocations, exports/forwarders e imports sob demanda via raízes explícitas; DllMain/TLS de DLLs e API-set pendentes |
| Ambiente Windows no emulador | Campos TEB/PEB, listas Ldr e consultas limitadas de debugger; versão explícita, campos desconhecidos bloqueados; não equivale a estado real capturado |
| ELF, unpacking completo, devirtualização e escrita nativa | Fases posteriores |
| Versão 0.2.0 | Código e documentação versionados; cobertura quantitativa publicada e benchmarks pendentes |

A seção 8.4 da proposta contém um erro aritmético no exemplo: `(125 ^ 53) + 12` resulta em **84**, não 88. O documento original foi preservado; a implementação mantém a semântica JVM e a cobre com testes.

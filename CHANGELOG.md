# Changelog

## 0.2.0 — 2026-10-04

- GUI para análise JVM/PE, recuperação de strings, edição de patches AMD64 e testes offline no Windows Sandbox.
- Comando `strings`: TXT separado para strings recuperadas e visíveis, relatório de evidências e JAR reconstruído com verificação ASM.
- Reconhecimento JVM de descriptografadores XOR sem exigir Base64 e Cipher sem exigir um estágio Base64.
- Scanner PE limitado de strings XOR constantes na stack, com orçamento de instruções/tempo e candidatos explicitamente identificados.
- Pacotes PowerShell com hash, assinatura, conferência de escrita e rollback; exemplos e documentação genéricos.
- Artefatos locais, amostras executáveis e estudos particulares excluídos da publicação.

## 0.1.0 — desenvolvimento

- Modo Windows `unpack --dump` para captura do módulo principal, com conferência do PID/arquivo, registro de lacunas e relatório associado; `--launch` inicia o alvo apenas quando solicitado explicitamente.

- Detecção heurística VMProtect, plano de capacidades e comando `unpack` com backend experimental Unicorn; captura de memória candidata em fixtures, sem reconstrução PE ou devirtualização automática.

- Core modular e CLI unificada para análise JVM e PE.
- JAR/CLASS: inspeção, análise, plano e verificação sem carregar classes alvo.
- Pipeline JVM extraído, seleção de transforms, registro de antes/depois e verificação de todas as classes da saída.
- Worker PE32/PE32+ com imports, exports, TLS, strings, entropia e overlay.
- Relatórios versionados JSON, texto e HTML; diff de metadados.
- Proteção de arquivos de entrada, limites ZIP compartilhados e testes sintéticos.
- NameRecovery e CLI legada preservados; removidos os caminhos pessoais padrão.

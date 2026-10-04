# Unveil Native — PE inicial

O worker PE usa [pefile](https://pefile.readthedocs.io/en/latest/modules/pefile.html) somente para leitura. Ele extrai PE32 e PE32+, arquitetura, subsistema, image base, entry point, seções com permissões, SHA-256 e entropia, imports normais e atrasados, exports, TLS callbacks e overlay.

Antes do parsing completo, valida cabeçalhos, tabela de seções e ranges físicos. Os TLS callbacks são lidos com tradução RVA → offset limitada a ranges físicos não ambíguos, com no máximo 1.024 entradas. Os endereços são dados; callbacks nunca são invocados. O Core limita o worker a 60 segundos.

Strings incluem ASCII e UTF-16LE restrito ao intervalo imprimível ASCII. São retornadas no máximo 10.000 strings e até 2.048 bytes por string, com sinalização de truncamento. Não são referências descobertas por disassembly.

A tabela de certificados é inventariada com offset e tamanho, sem verificação criptográfica. O overlay inclui certificados presentes após a última seção. Resources, relocations, debug e unwind são listados como diretórios, mas ainda não são decodificados. Entropia por janela, CFG, disassembly e ELF ficam nas próximas fases.

O teste `tests/framework_fixtures.py` gera fixtures próprias PE32/PE32+ com imports, exports e callbacks TLS. Esses arquivos nunca são executados; seus bytes são usados apenas para testar extração e rejeição de formatos inválidos.

# Segurança

Unveil trata JARs e executáveis como dados não confiáveis. A análise não invoca classes, inicializadores, DLL entry points ou TLS callbacks do alvo. O interpretador JVM modela somente operações permitidas; o helper Java contém código do próprio projeto.

Entradas não podem coincidir com saídas ou relatórios, inclusive por hardlinks nos novos fluxos. ZIPs possuem limites de entradas e bytes descompactados declarados. Não há extração de caminhos fornecidos pelo JAR para o filesystem. Relatórios HTML escapam os dados da amostra.

O worker PE possui timeout, mas não é uma sandbox do sistema operacional. O consumo de memória dos parsers e modelos pode exceder o tamanho do arquivo. Plugins registrados manualmente são código confiável com as permissões do processo.

O comando experimental `unpack --emulate` permite emulação limitada de instruções de CPU em processo filho. Não inicia o executável como processo Windows nem encaminha APIs/syscalls ao host. TLS e outras dependências Windows não modeladas interrompem a tentativa. Capturas são memória candidata, nunca declaradas automaticamente como executáveis desprotegidos. Veja os limites e pressupostos em `docs/unpacker.md`.

`unpack --dump` lê um processo Windows explicitamente indicado por PID/nome. Somente `--dump --launch` inicia o EXE de entrada como programa real, com as permissões do usuário, incluindo acesso normal a rede e arquivos. Esse processo permanece rodando após a captura. Essa opção não é uma sandbox. A leitura do módulo principal confere a identidade do arquivo e registra regiões que não puderam ser lidas; não injeta código nem escreve na memória do alvo.

Relatórios podem conter strings recuperadas e informações privadas. Use somente software próprio, fixtures de laboratório ou amostras cuja análise seja autorizada. Para relatar uma vulnerabilidade, compartilhe uma reprodução mínima e gerada, sem publicar amostras privadas ou credenciais. Ainda não há canal privado de divulgação configurado neste repositório.

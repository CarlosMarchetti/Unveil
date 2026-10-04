# NameRecovery

O estágio separa análise e aplicação. Execute primeiro os passes de deobfuscation: constantes, strings e pools simplificados melhoram a comparação. Nenhum JAR analisado é executado ou colocado no classpath do helper.

## Comparação e sugestões

O comparador normaliza instruções, expressões constantes e referências internas. Combina fingerprints de classes e métodos com relações de herança e chamadas. Correspondências parciais ficam disponíveis para revisão. Campos são comparados por tipos, acesso e padrões de uso; a posição na classe não basta.

Classes com helpers adicionados pelo obfuscador podem ser confirmadas mesmo sem igualdade completa. Para isso, o comparador exige métodos exclusivos nos dois JARs, vencedor nos dois sentidos com margem mínima de três vezes sobre concorrentes, e cobertura suficiente da referência. São necessários pelo menos quatro métodos e 60% de cobertura, ou três métodos e 25% de cobertura com concordância adicional de herança/interface. Os bloqueios de segurança continuam sendo aplicados. Os relatórios distinguem propostas pendentes de revisão, nomes aprovados e entradas bloqueadas; a quantidade total de classes inclui bibliotecas que já podem ter nomes legíveis.

O nome de referência é transferido mantendo o pacote original do client, para reduzir alterações de acesso entre pacotes. Portanto o resultado não reproduz necessariamente a árvore de pacotes MCP. Mappings de referência devem mapear o namespace real do JAR de referência para os nomes desejados.

Regras semânticas reconhecem indicadores de descriptografia, pools, armazenamento e comunicação HTTP. Cada proposta registra origem, confiança e evidências. Uma classe própria sem evidências suficientes mantém seu nome. Confiança é uma classificação heurística, não uma probabilidade ou prova de equivalência.

## Comandos

```powershell
python main.py client-deobf.jar --recover-names --reference minecraft-1.5.2.jar --reference-mappings client.srg --mcp-dir conf --names-dir names
python main.py client-deobf.jar client-named.jar --apply-mappings names/approved-mappings.json --names-dir applied
```

Para analisar e aplicar os candidatos aprovados de uma vez:

```powershell
python main.py client-deobf.jar client-named.jar --recover-names --reference reference.jar --reference-mappings reference.tiny --names-dir names
```

Use `--seed-mappings client.tiny` para mappings cujo namespace de origem já corresponde ao client. Tiny v1/v2 utiliza o primeiro namespace como origem e o último como destino. Tiny com nomes escapados e sessões nativas `.match` não são aceitos. SRG aceita CL/MD/FD; entradas PK não são aplicadas. Campos SRG sem descritor precisam corresponder a uma declaração única. `--mcp-dir` traduz nomes SRG usando `methods.csv` e `fields.csv` do lado cliente ou comum.

`--offline` impede downloads de dependências; o helper deve ter sido preparado numa execução anterior. A comparação e a inferência em si são locais.

## Artefatos e revisão

- `name-recovery.json`: contagens, evidências, relações, itens bloqueados, erros e resultado de validação.
- `mappings.json`: todas as propostas, inclusive as não aprovadas.
- `approved-mappings.json`: somente o conjunto aprovado após as restrições de segurança, incluindo propagação por herança.
- `approved-mappings.tiny`: exportação do conjunto aprovado.

Exemplo de mapping manual (nomes e descritores sempre no namespace de entrada):

```json
{
  "format": "unveil-mappings-v1",
  "classes": [
    {"from": "client/IlIl", "to": "client/LoginScreen", "approved": true, "origin": "manual"}
  ],
  "methods": [
    {"owner": "client/IlIl", "from": "a", "descriptor": "(Ljava/lang/String;)V", "to": "setUsername", "approved": true, "origin": "manual"}
  ],
  "fields": []
}
```

Os arquivos gerados incluem `sourceSHA256`; aplicação sobre outro JAR é rejeitada. Preserve esse campo ao revisar. Use um diretório diferente para o relatório da aplicação, para não sobrescrever seu mapping de entrada.

Sugestões inferidas começam não aprovadas. A opção `--accept-inferred` considera as de confiança alta; membros inferidos precisam ser privados para aplicação automática. Aprovar uma entrada não contorna colisões e demais restrições. Na aplicação explícita, qualquer mapping aprovado bloqueado rejeita a operação inteira; revise o relatório.

## Reescrita e segurança

Python resolve declarações, famílias de métodos virtuais e referências herdadas. O helper ASM aplica o plano, remapeando descritores, frames e referências de bytecode. O fluxo de controle não é alterado. Manifesto e arquivos `META-INF/services` têm adaptação específica; assinaturas antigas e índices inválidos são removidos. Outros recursos mantêm seus bytes.

O arquivo temporário é reaberto, tem CRC e classes conferidos e passa novamente pela verificação ASM (`CheckClassAdapter` e análise de bytecode). Somente depois substitui o destino. Uma falha preserva o destino anterior: renomeações não podem usar o fallback por classe dos passes de simplificação, pois isso quebraria referências cruzadas.

Há bloqueios para colisões, novos overrides/hiding, famílias incompatíveis, referências indiretas reconhecidas, JNI, serialização Java, enumerações e anotações. Mudanças de pacote exigem mover todo o pacote de origem de forma consistente. JARs multi-release ou com classes não parseáveis são rejeitados neste estágio.

Essas verificações são conservadoras e incompletas: nomes construídos dinamicamente, consumidores externos, serializers por reflexão e contratos de plugins podem não ser observáveis. ASM valida estrutura e tipos de bytecode, mas não prova que todos os vínculos externos e comportamentos em execução permanecerão corretos. Mantenha o original e revise os mappings antes de usar o resultado em seu ambiente.

## Testes

```powershell
python -m unittest discover -s tests -v
python tests/integration.py
python tests/names_integration.py
```

Somente fixtures próprias são executadas. A integração de nomes cobre herança, métodos, campos, lambdas, serviços, manifesto, recursos, importação, comparação estrutural e rejeição atômica de planos inválidos.

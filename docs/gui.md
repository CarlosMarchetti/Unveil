# Unveil Patch Workbench

Abra `Abrir-Unveil-GUI.cmd` na raiz do repositório, ou execute:

```powershell
python -m unveil.gui
python -m unveil.gui --sample "C:\caminho\programa.exe"
python -m unveil.gui --project "C:\caminho\projeto.json"
```

Exige Python 3.10+ com Tkinter e as dependências de `requirements.txt`.
A GUI aceita JAR, CLASS, EXE e DLL para análise e recuperação de strings.
O editor de patches PS1 e o launcher Sandbox exigem EXE AMD64.
Selecionar, analisar, buscar e exportar não executa a amostra.

## Fluxo de trabalho

1. **Amostra:** selecione JVM ou PE e analise pelo motor do Unveil. O projeto de patches registra
   SHA-256 e tamanho do módulo. A captura por PID lê um processo já existente da
   mesma amostra; não o inicia. O PID do Sandbox não é acessível pelo host.
2. **Busca:** procure strings ASCII/UTF-16LE ou sequências hexadecimais no EXE
   ou dump. Em arquivo PE, a GUI converte offset físico para RVA pelas seções.
   Em `.mapped.bin`, marque layout de memória: offset corresponde ao RVA.
   Overlay não possui RVA utilizável para patch do módulo.
3. **Patches:** use um resultado para preencher o RVA, leia a assinatura e
   informe os bytes novos. Os modelos de retorno AMD64 são atalhos de bytes;
   precisam ser usados no início correto de uma função e com o contrato de
   chamada verificado. O botão de troca de texto mantém terminador e tamanho.
   Salve projetos e importe listas JSON existentes com os campos `name`, `rva`
   (inteiro), `expectedHex` e `patchHex`.

Na aba **Strings**, exporte os textos recuperados e visíveis, o relatório e,
para JAR, a saída reconstruída e verificada. A opção offline usa as dependências
ASM já instaladas. Veja [recuperação de strings](decrypt.md) para cobertura.
4. **Sandbox:** configure o título exato da janela que deve surgir antes das
   alterações, RAM e captura opcional. Exporte um novo pacote e abra o Sandbox.
   Windows Sandbox deve estar instalado e com o hipervisor funcionando; a GUI
   não habilita recursos do Windows nem altera boot ou BIOS.
5. **Resultado:** importe o `result.json` da sessão pela aba Busca. Se houver
   `module.mapped.bin` ao lado, ele será selecionado com layout de memória.
   O registro mostra verificações, falhas e páginas ausentes da captura.

## Pacote exportado

```text
Unveil-patch-<data>/
  windows/Aplicar-Patch.cmd
  windows/Aplicar-Patch.ps1
  windows/input/{sample.exe,patch.ps1,runtime.json}
  windows-sandbox/Abrir-Sandbox.cmd
  windows-sandbox/Abrir-Sandbox.ps1
  windows-sandbox/input/{sample.exe,patch.ps1,runtime.json}
  project.json
  LEIA-ME.md
  SHA256.json
```

Cada pasta de execução contém sua própria amostra e scripts e dispensa Python.
O exportador copia apenas o EXE: dependências externas, DLLs auxiliares e dados
necessários ao programa precisam ser considerados separadamente. `project.json`
guarda o caminho da amostra para edição local; os aplicadores usam caminhos
relativos. O manifesto inclui hashes dos arquivos exportados.

O launcher Windows inicia a cópia do EXE ou usa o único processo correspondente;
um PID também pode ser informado com `-ProcessId`. Isso executa o programa no
host antes dos patches. Para testes isolados, use a outra pasta.

O launcher Sandbox gera um `.wsb` com caminhos atuais, entrada somente leitura,
saída dedicada por sessão, rede e redirecionamentos desativados. Dentro do
Sandbox, o EXE é copiado para uma pasta temporária antes de iniciar. Somente a
pasta de saída é compartilhada com escrita no host.

## Aplicação e limites

O PS1 confere o hash antes de iniciar, espera até 60 segundos pelo título e
pelas assinaturas, suspende o processo e reconfere todas antes da primeira
escrita. Aplica os bytes, restaura proteção das páginas, atualiza o cache de
instruções e verifica o resultado. Uma falha provoca tentativa de rollback das
alterações realizadas, inclusive a escrita que falhou parcialmente. O processo
é retomado e o resultado é registrado em JSON.

O título da janela é uma condição configurável: não comprova, por si só, que
todas as verificações de integridade do programa terminaram. Assinaturas podem
depender de relocations ou de dados que mudam a cada execução. O relatório
separa escrita verificada de funcionamento do aplicativo, que exige observação.

A primeira versão cobre patches de bytes e textos que cabem no espaço original.
Não automatiza alocação de strings maiores, redirecionamento de ponteiros,
troca de HICON/GDI ou helpers que mantêm recursos gráficos vivos. Esses mecanismos
exigem implementações especializadas; importar uma lista de bytes não os substitui.

A busca lê strings visíveis; não decripta automaticamente strings protegidas.
Capturas são imagens mapeadas por RVA, com possíveis páginas ausentes e sem
garantia de snapshot atômico. Não são um EXE original recuperado nem uma prova
de remoção completa de VMProtect.

## Validação

```powershell
python -m unveil.gui --smoke-test
python -m unittest discover -s tests -p test_gui_workbench.py -v
```

Os testes usam um PE de autoria local como dado, sem executá-lo. Cobrem
endereçamento, limites, sobreposição, persistência, hash, exportação e três
cenários PowerShell com memória simulada: sucesso, rollback e assinatura
alterada entre a espera e a suspensão. A simulação valida a lógica do PS1;
não substitui um teste real do aplicativo dentro do Sandbox.

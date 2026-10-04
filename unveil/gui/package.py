"""Export self-contained PS1 launchers and an offline Windows Sandbox configuration."""
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from .model import Project, read_bounded

HASH_FUNCTION = r'''function SampleHash([string]$path) {
 $stream=[IO.File]::OpenRead($path); $sha=[Security.Cryptography.SHA256]::Create()
 try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
 finally { $sha.Dispose(); $stream.Dispose() }
}
'''

WINDOWS_LAUNCHER = r'''param([int]$ProcessId=0)
$ErrorActionPreference='Stop'
$inputFolder=Join-Path $PSScriptRoot 'input'
$sample=Join-Path $inputFolder 'sample.exe'
$config=Get-Content -LiteralPath (Join-Path $inputFolder 'runtime.json') -Raw | ConvertFrom-Json
if ((SampleHash $sample) -ne $config.sha256) { throw 'Hash divergente. Partida cancelada.' }
if ($ProcessId -eq 0) {
 $candidates=@(Get-Process -Name 'sample' -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq $sample})
 if ($candidates.Count -gt 1) { throw 'Mais de um alvo. Informe -ProcessId.' }
 if ($candidates.Count -eq 1) { $ProcessId=$candidates[0].Id }
}
$output=Join-Path $PSScriptRoot ('output\session-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
Write-Output "Relatorio: $output\result.json"
& (Join-Path $inputFolder 'patch.ps1') -InputFolder $inputFolder -OutputFolder $output -ExistingProcessId $ProcessId -Launch
'''

SANDBOX_LAUNCHER = r'''$ErrorActionPreference='Stop'
$sandbox=Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'
if (-not (Test-Path -LiteralPath $sandbox)) { throw 'Windows Sandbox nao esta disponivel. Habilite o recurso do Windows.' }
$inputFolder=Join-Path $PSScriptRoot 'input'
$config=Get-Content -LiteralPath (Join-Path $inputFolder 'runtime.json') -Raw | ConvertFrom-Json
if ((SampleHash (Join-Path $inputFolder 'sample.exe')) -ne $config.sha256) { throw 'Hash da amostra divergente.' }
if ($config.memoryMB -lt 2048 -or $config.memoryMB -gt 8192) { throw 'RAM invalida.' }
$output=Join-Path $PSScriptRoot ('output\session-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $output | Out-Null
[xml]$wsb=@'
<Configuration>
 <Networking>Disable</Networking><vGPU>Disable</vGPU><ClipboardRedirection>Disable</ClipboardRedirection>
 <AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput><PrinterRedirection>Disable</PrinterRedirection>
 <ProtectedClient>Enable</ProtectedClient><MemoryInMB>4096</MemoryInMB>
 <MappedFolders>
  <MappedFolder><HostFolder></HostFolder><SandboxFolder>C:\UnveilInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
  <MappedFolder><HostFolder></HostFolder><SandboxFolder>C:\UnveilOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
 </MappedFolders>
 <LogonCommand><Command>powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\UnveilInput\patch.ps1 -InputFolder C:\UnveilInput -OutputFolder C:\UnveilOutput -Launch -Sandbox</Command></LogonCommand>
</Configuration>
'@
$wsb.Configuration.MemoryInMB=[string]$config.memoryMB
$wsb.SelectSingleNode('//MappedFolder[ReadOnly="true"]/HostFolder').InnerText=$inputFolder
$wsb.SelectSingleNode('//MappedFolder[ReadOnly="false"]/HostFolder').InnerText=$output
$path=Join-Path $output 'Unveil.wsb'; $wsb.Save($path)
Write-Output "Saida da sessao: $output"
Start-Process -FilePath $sandbox -ArgumentList ('"'+$path+'"') -WindowStyle Hidden
'''

README = '''# Pacote gerado pelo Unveil GUI

Windows: abra windows/Aplicar-Patch.cmd. O programa original é iniciado antes
da aplicação dos patches. O aplicador aguarda o título configurado e as
assinaturas. Isso não oferece isolamento nem bloqueia ações anteriores.

Sandbox: abra windows-sandbox/Abrir-Sandbox.cmd. Exige Windows Sandbox já
instalado e o hipervisor funcionando. Rede e redirecionamentos são desativados;
entrada somente leitura e saída em uma pasta dedicada. O Unveil não modifica
automaticamente BIOS, Defender, recursos opcionais ou configuração de boot.

Os scripts conferem o SHA-256 e todas as assinaturas antes da primeira escrita.
As permissões são restauradas, os bytes conferidos e o processo retomado.
Falha em uma escrita provoca tentativa de rollback, registrada no relatório.

Leia output/session-*/result.json para conferir as escritas e possíveis erros.
Uma escrita verificada não comprova que o aplicativo funcione corretamente.
Se a captura estiver habilitada, module.mapped.bin é uma imagem por RVA:
carregue-a na GUI com o layout “memória”. Páginas ausentes estão no relatório.
Não é um EXE desprotegido e não comprova remoção de VMProtect.

Projetos sem patches servem como teste de controle da amostra sem alterações.
Não distribua output se ele contiver dados de suas sessões. O exportador só
gera arquivos; não executa a amostra.
'''


def export_package(project: Project, destination: Path) -> Path:
    project = project.validated()
    source = Path(project.source).resolve(strict=True)
    destination = destination.resolve()
    if not destination.parent.is_dir():
        raise ValueError('A pasta pai da exportação não existe.')
    if destination == source or source.is_relative_to(destination):
        raise ValueError('Exporte fora da pasta que contém a amostra.')
    if destination.exists():
        raise ValueError('Escolha uma pasta nova; arquivos existentes não são sobrescritos.')
    data = read_bounded(source)
    actual = Project.open_sample(str(source))
    if hashlib.sha256(data).hexdigest() != project.sha256 or actual.sha256 != project.sha256 or actual.image_size != project.image_size:
        raise ValueError('A amostra mudou desde que o projeto foi criado.')
    runtime = Path(__file__).with_name('runtime.ps1').read_text(encoding='utf-8')
    config = dict(version=1, sha256=project.sha256, imageSize=project.image_size,
                  title=project.title, capture=project.capture, memoryMB=project.memory_mb,
                  patches=[p.runtime() for p in project.patches])
    # Publish only a complete package. A failed generation leaves no partial destination.
    with tempfile.TemporaryDirectory(prefix='unveil-export-', dir=destination.parent) as temporary:
        root = Path(temporary) / 'package'
        root.mkdir()
        for name, launcher, entry in [('windows', WINDOWS_LAUNCHER, 'Aplicar-Patch'),
                                     ('windows-sandbox', SANDBOX_LAUNCHER, 'Abrir-Sandbox')]:
            folder = root / name
            input_folder = folder / 'input'
            input_folder.mkdir(parents=True)
            (input_folder / 'sample.exe').write_bytes(data)
            (input_folder / 'patch.ps1').write_text(runtime, encoding='utf-8-sig')
            (input_folder / 'runtime.json').write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding='utf-8-sig')
            if name == 'windows':
                launcher = launcher.replace("$ErrorActionPreference='Stop'", "$ErrorActionPreference='Stop'\n" + HASH_FUNCTION, 1)
            else:
                launcher = HASH_FUNCTION + launcher
            (folder / f'{entry}.ps1').write_text(launcher, encoding='utf-8-sig')
            (folder / f'{entry}.cmd').write_text(
                '@echo off\r\n"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
                f'-NoProfile -ExecutionPolicy Bypass -File "%~dp0{entry}.ps1" %*\r\npause\r\n', encoding='ascii')
        (root / 'LEIA-ME.md').write_text(README, encoding='utf-8')
        project.save(root / 'project.json')
        hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(root.rglob('*')) if p.is_file()}
        (root / 'SHA256.json').write_text(json.dumps(hashes, indent=2), encoding='utf-8')
        if destination.exists():
            raise ValueError('A pasta de destino foi criada por outra operação.')
        root.rename(destination)
    return destination


def suggested_destination(parent: Path) -> Path:
    return parent / ('Unveil-patch-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))


def open_sandbox(package: Path) -> str:
    if os.name != 'nt':
        raise ValueError('Windows Sandbox só pode ser aberto no Windows.')
    script = package.resolve() / 'windows-sandbox' / 'Abrir-Sandbox.ps1'
    if not script.is_file():
        raise ValueError('Exporte um pacote antes de abrir o Sandbox.')
    powershell = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                             '-File', str(script)], capture_output=True, text=True, timeout=30,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise ValueError((result.stderr or result.stdout).strip()[:3000])
    return result.stdout.strip()

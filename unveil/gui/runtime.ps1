param([string]$InputFolder=$PSScriptRoot,[Parameter(Mandatory=$true)][string]$OutputFolder,[int]$ExistingProcessId=0,[switch]$Launch,[switch]$Sandbox)
$ErrorActionPreference='Stop'
function SampleHash([string]$path) {
 $stream=[IO.File]::OpenRead($path); $sha=[Security.Cryptography.SHA256]::Create()
 try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
 finally { $sha.Dispose(); $stream.Dispose() }
}
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$report=@{startedAt=(Get-Date).ToString('o');patched=$false;verified=@();memoryLayout='RVA';sandbox=[bool]$Sandbox}
$handle=[IntPtr]::Zero
try {
 if (-not [Environment]::Is64BitProcess) { throw 'Use PowerShell de 64 bits.' }
 $config=Get-Content -LiteralPath (Join-Path $InputFolder 'runtime.json') -Raw | ConvertFrom-Json
 if ($config.sha256 -notmatch '^[0-9a-f]{64}$' -or $config.imageSize -le 0 -or $config.imageSize -gt 134217728 -or -not $config.title -or $config.title.Length -gt 256 -or @($config.patches).Count -gt 128) { throw 'Configuracao invalida.' }
 $sample=Join-Path $InputFolder 'sample.exe'
 if ((SampleHash $sample) -ne $config.sha256) { throw 'Hash da amostra divergente.' }
 function HexBytes([string]$value) {
  if ($value -notmatch '^(?:[0-9a-fA-F]{2}){1,4096}$') { throw 'Hexadecimal invalido.' }
  [byte[]]$bytes=for($i=0;$i -lt $value.Length;$i+=2){[Convert]::ToByte($value.Substring($i,2),16)}
  return ,$bytes
 }
 $specs=@(foreach($spec in $config.patches) {
  $expected=HexBytes $spec.expectedHex; $patch=HexBytes $spec.patchHex
  if ($spec.rva -lt 0 -or $spec.rva+[int64]$expected.Length -gt $config.imageSize -or $patch.Length -gt $expected.Length) { throw 'Intervalo de patch invalido.' }
  $after=$expected.Clone(); [Array]::Copy($patch,$after,$patch.Length)
  @{name=$spec.name;rva=[int64]$spec.rva;expected=$expected;patch=$patch;after=$after}
 })
 $ordered=@($specs | Sort-Object { $_.rva })
 for($i=1;$i -lt $ordered.Count;$i++) {
  if ($ordered[$i-1].rva+$ordered[$i-1].expected.Length -gt $ordered[$i].rva) { throw 'Assinaturas sobrepostas.' }
 }
 Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class UnveilPatchMemory {
 [DllImport("kernel32",SetLastError=true)] public static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32",SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr process,IntPtr address,byte[] bytes,UIntPtr length,out UIntPtr copied);
 [DllImport("kernel32",SetLastError=true)] public static extern bool WriteProcessMemory(IntPtr process,IntPtr address,byte[] bytes,UIntPtr length,out UIntPtr copied);
 [DllImport("kernel32",SetLastError=true)] public static extern bool VirtualProtectEx(IntPtr process,IntPtr address,UIntPtr length,uint protection,out uint previous);
 [DllImport("kernel32",SetLastError=true)] public static extern bool FlushInstructionCache(IntPtr process,IntPtr address,UIntPtr length);
 [DllImport("kernel32")] public static extern bool CloseHandle(IntPtr handle);
 [DllImport("ntdll")] public static extern int NtSuspendProcess(IntPtr process);
 [DllImport("ntdll")] public static extern int NtResumeProcess(IntPtr process);
 public sealed class Snapshot { public byte[] Bytes; public int[] MissingPages; }
 public static Snapshot Capture(IntPtr process,long address,int size) {
  byte[] image=new byte[size]; var missing=new List<int>();
  for(int offset=0;offset<size;offset+=4096) {
   byte[] page=new byte[Math.Min(4096,size-offset)]; UIntPtr copied;
   bool ok=ReadProcessMemory(process,new IntPtr(address+offset),page,new UIntPtr((uint)page.Length),out copied);
   int count=(int)copied.ToUInt64(); if(!ok || count!=page.Length) missing.Add(offset);
   Array.Copy(page,0,image,offset,count);
  }
  return new Snapshot { Bytes=image, MissingPages=missing.ToArray() };
 }
}
'@
 if ($Sandbox) {
  if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $InputFolder -ne 'C:\UnveilInput') { throw 'Contexto de Sandbox invalido.' }
  $targetFolder=Join-Path $env:TEMP ('Unveil-'+[Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $targetFolder | Out-Null
  $sample=Join-Path $targetFolder 'sample.exe'
  Copy-Item -LiteralPath (Join-Path $InputFolder 'sample.exe') -Destination $sample
  if ((SampleHash $sample) -ne $config.sha256) { throw 'Amostra mudou durante a copia.' }
 }
 if ($ExistingProcessId -gt 0) {
  $target=Get-Process -Id $ExistingProcessId
  if ($target.MainModule.FileName -ne $sample) { throw 'O PID nao pertence a copia deste pacote.' }
 } elseif ($Launch) {
  $target=Start-Process -FilePath $sample -WorkingDirectory (Split-Path $sample -Parent) -PassThru
 } else { throw 'Informe um PID ou a opcao Launch.' }
 $report.pid=$target.Id
 $handle=[UnveilPatchMemory]::OpenProcess(0xc38,$false,$target.Id)
 if ($handle -eq [IntPtr]::Zero) { throw 'OpenProcess falhou.' }
 $base=$target.MainModule.BaseAddress.ToInt64()
 if ($target.MainModule.ModuleMemorySize -ne $config.imageSize) { throw 'Tamanho do modulo divergente.' }
 $report.imageBase=$base
 function ReadBytes([int64]$rva,[int]$length) {
  $bytes=New-Object byte[] $length; $copied=[UIntPtr]::Zero
  if (-not [UnveilPatchMemory]::ReadProcessMemory($handle,[IntPtr]($base+$rva),$bytes,[UIntPtr]::new([uint64]$length),[ref]$copied) -or $copied.ToUInt64() -ne $length) { throw 'Leitura parcial de memoria.' }
  return ,$bytes
 }
 function EqualBytes([byte[]]$a,[byte[]]$b) { return [Convert]::ToBase64String($a) -eq [Convert]::ToBase64String($b) }
 function WriteBytes([int64]$rva,[byte[]]$bytes) {
  $address=[IntPtr]($base+$rva); $size=[UIntPtr]::new([uint64]$bytes.Length)
  $old=[uint32]0; $copied=[UIntPtr]::Zero
  if (-not [UnveilPatchMemory]::VirtualProtectEx($handle,$address,$size,0x40,[ref]$old)) { throw 'Falha ao permitir escrita.' }
  try {
   if (-not [UnveilPatchMemory]::WriteProcessMemory($handle,$address,$bytes,$size,[ref]$copied) -or $copied.ToUInt64() -ne $bytes.Length) { throw 'Escrita parcial.' }
   if (-not [UnveilPatchMemory]::FlushInstructionCache($handle,$address,$size)) { throw 'Falha ao atualizar cache de instrucoes.' }
  } finally {
   $unused=[uint32]0
   if (-not [UnveilPatchMemory]::VirtualProtectEx($handle,$address,$size,$old,[ref]$unused)) { throw 'Falha ao restaurar protecao.' }
  }
  if (-not (EqualBytes (ReadBytes $rva $bytes.Length) $bytes)) { throw 'Conferencia da escrita falhou.' }
 }
 $deadline=[DateTime]::UtcNow.AddSeconds(60); $ready=$false
 while([DateTime]::UtcNow -lt $deadline) {
  $target.Refresh(); if ($target.HasExited) { throw 'O alvo encerrou antes do patch.' }
  if ($target.MainWindowTitle -eq $config.title) {
   try {
    foreach($spec in $specs) {
     $actual=ReadBytes $spec.rva $spec.expected.Length
     if (-not (EqualBytes $actual $spec.expected) -and -not (EqualBytes $actual $spec.after)) { throw ('Assinatura divergente: '+$spec.name) }
    }
    $ready=$true; break
   } catch { $report.lastSignatureError=$_.Exception.Message }
  }
  Start-Sleep -Milliseconds 200
 }
 if (-not $ready) { throw 'Janela e assinaturas nao observadas em 60 segundos.' }
 $report.observedTitle=$target.MainWindowTitle
 if ([UnveilPatchMemory]::NtSuspendProcess($handle) -lt 0) { throw 'Falha ao suspender alvo.' }
 $changed=New-Object Collections.ArrayList
 try {
  # Validate all signatures before the first write, while the process is suspended.
  foreach($spec in $specs) {
   $actual=ReadBytes $spec.rva $spec.expected.Length
   if (-not (EqualBytes $actual $spec.expected) -and -not (EqualBytes $actual $spec.after)) { throw ('Assinatura mudou: '+$spec.name) }
  }
  foreach($spec in $specs) {
   if (EqualBytes (ReadBytes $spec.rva $spec.expected.Length) $spec.after) { $report.verified+=@{name=$spec.name;alreadyApplied=$true}; continue }
   [void]$changed.Add($spec) # Include a write attempt even if it fails part-way.
   WriteBytes $spec.rva $spec.patch
   $report.verified+=@{name=$spec.name;alreadyApplied=$false}
  }
  $report.patched=$true
 } catch {
  $report.rollbackErrors=@()
  for($i=$changed.Count-1;$i -ge 0;$i--) {
   try { WriteBytes $changed[$i].rva $changed[$i].expected }
   catch { $report.rollbackErrors+=$_.Exception.Message }
  }
  throw
 } finally {
  $report.resumed=([UnveilPatchMemory]::NtResumeProcess($handle) -ge 0)
  if (-not $report.resumed) { throw 'Falha ao retomar o processo.' }
 }
 if ($config.capture) {
  $snapshot=[UnveilPatchMemory]::Capture($handle,$base,[int]$config.imageSize)
  [IO.File]::WriteAllBytes((Join-Path $OutputFolder 'module.mapped.bin'),$snapshot.Bytes)
  $report.captureMissingPages=$snapshot.MissingPages
  $report.capture='module.mapped.bin'
  $report.captureAtomic=$false
 }
 $target.Refresh(); $report.targetAlive=-not $target.HasExited
 $report.functionalOutcome='not-validated'
} catch { $report.error=$_.Exception.Message }
finally {
 if ($handle -ne [IntPtr]::Zero) { [void][UnveilPatchMemory]::CloseHandle($handle) }
 $report.finishedAt=(Get-Date).ToString('o')
 $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputFolder 'result.json') -Encoding UTF8
}
if ($report.error) { throw $report.error }

param([string]$Package,[string]$Mode='success')
$ErrorActionPreference='Stop'
if ($Mode -eq 'compile') {
 foreach($file in Get-ChildItem -LiteralPath $Package -Recurse -Filter '*.ps1') {
  $tokens=$null; $errors=$null
  [System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors) | Out-Null
  if ($errors.Count) {throw ($errors | Out-String)}
 }
 $runtime=Get-Content -LiteralPath (Join-Path $Package 'windows\input\patch.ps1') -Raw
 $native=[regex]::Match($runtime,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@")
 if (-not $native.Success) {throw 'Missing native helper.'}
 Add-Type -TypeDefinition $native.Groups[1].Value
 @{mode=$Mode;passed=$true;targetExecuted=$false} | ConvertTo-Json -Compress
 return
}
# Simulated memory only. The authored sample is never started or mapped.
Add-Type -TypeDefinition @'
using System;
public static class UnveilPatchMemory {
 public static byte[] Memory=new byte[8192];
 public static int Writes=0, Suspends=0, Resumes=0;
 public static bool FailOnce=false, ChangeOnSuspend=false;
 public static IntPtr OpenProcess(uint access,bool inherit,int pid){return new IntPtr(1);}
 public static bool ReadProcessMemory(IntPtr p,IntPtr a,byte[] b,UIntPtr n,out UIntPtr copied){
  Array.Copy(Memory,a.ToInt64()-1048576,b,0,(long)n.ToUInt64());copied=n;return true;
 }
 public static bool WriteProcessMemory(IntPtr p,IntPtr a,byte[] b,UIntPtr n,out UIntPtr copied){
  Writes++;Array.Copy(b,0,Memory,a.ToInt64()-1048576,(long)n.ToUInt64());copied=n;
  if(FailOnce && Writes==2){copied=UIntPtr.Zero;return false;}return true;
 }
 public static bool VirtualProtectEx(IntPtr p,IntPtr a,UIntPtr n,uint v,out uint old){old=32;return true;}
 public static bool FlushInstructionCache(IntPtr p,IntPtr a,UIntPtr n){return true;}
 public static bool CloseHandle(IntPtr p){return true;}
 public static int NtSuspendProcess(IntPtr p){Suspends++;if(ChangeOnSuspend)Memory[4112]=255;return 0;}
 public static int NtResumeProcess(IntPtr p){Resumes++;return 0;}
}
'@
# The runtime's Add-Type is intercepted after the fake type exists. No native APIs.
function Add-Type { param($TypeDefinition) }
function Start-Process { throw 'Unexpected target execution in mock test.' }
$inputFolder=Join-Path $Package 'windows\input'
$global:unveilMockTarget=[pscustomobject]@{
 Id=4242;MainModule=[pscustomobject]@{FileName=(Join-Path $inputFolder 'sample.exe');BaseAddress=[IntPtr]1048576;ModuleMemorySize=8192};
 MainWindowTitle='Fixture';HasExited=$false
}
$global:unveilMockTarget | Add-Member -MemberType ScriptMethod -Name Refresh -Value {}
function Get-Process { param($Id) return $global:unveilMockTarget }
[UnveilPatchMemory]::Memory[4096]=170
[UnveilPatchMemory]::Memory[4112]=187
[UnveilPatchMemory]::FailOnce=($Mode -eq 'rollback')
[UnveilPatchMemory]::ChangeOnSuspend=($Mode -eq 'signature')
$output=Join-Path $Package ('test-output-'+$Mode)
$errorText=$null
try { & (Join-Path $inputFolder 'patch.ps1') -InputFolder $inputFolder -OutputFolder $output -ExistingProcessId 4242 }
catch {$errorText=$_.Exception.Message}
$report=Get-Content -LiteralPath (Join-Path $output 'result.json') -Raw | ConvertFrom-Json
if ($errorText) { Write-Output ('Runtime error: '+$errorText) }
if ($Mode -eq 'success') {
 if ($errorText -or -not $report.patched -or [UnveilPatchMemory]::Writes -ne 2 -or [UnveilPatchMemory]::Memory[4096] -ne 204 -or [UnveilPatchMemory]::Memory[4112] -ne 221) {throw 'Success path failed.'}
} elseif ($Mode -eq 'rollback') {
 if (-not $errorText -or $report.patched -or @($report.rollbackErrors).Count -ne 0 -or [UnveilPatchMemory]::Memory[4096] -ne 170 -or [UnveilPatchMemory]::Memory[4112] -ne 187) {throw 'Rollback failed.'}
} elseif ($Mode -eq 'signature') {
 if (-not $errorText -or [UnveilPatchMemory]::Writes -ne 0) {throw 'Signature gate failed.'}
} else {throw 'Unknown mode.'}
if ([UnveilPatchMemory]::Suspends -ne 1 -or [UnveilPatchMemory]::Resumes -ne 1) {throw 'Suspend/resume mismatch.'}
@{mode=$Mode;passed=$true;targetExecuted=$false;writes=[UnveilPatchMemory]::Writes} | ConvertTo-Json -Compress

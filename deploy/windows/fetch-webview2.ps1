# Baja el Evergreen Bootstrapper de WebView2 del enlace oficial de Microsoft y comprueba que su firma Authenticode es
# válida y de Microsoft Corporation antes de que entre al instalador. Uso: fetch-webview2.ps1 -Out <ruta.exe>
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = 'Stop'
Invoke-WebRequest -UseBasicParsing -Uri 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $Out
$sig = Get-AuthenticodeSignature -FilePath $Out
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
  Remove-Item -Force $Out
  throw "bootstrapper de WebView2 con firma inválida: $($sig.Status) $($sig.SignerCertificate.Subject)"
}
Write-Host "bootstrapper de WebView2 verificado: $($sig.SignerCertificate.Subject)"

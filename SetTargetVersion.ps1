###########################################################
#  By Proliantaholic https://proliantaholic.blogspot.com  #
###########################################################

# Elevate Powershell to Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

$osInfo = Get-CimInstance Win32_OperatingSystem
$WindowsCaption = $osInfo.Caption -replace 'Microsoft ', ''
$osArch = $osInfo.OSArchitecture -replace '(..)(.*)', '$1-bit'
$WindowsInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$CurrentBuild = $WindowsInfo.CurrentBuild
$CurrentUBR = $WindowsInfo.UBR
if ($CurrentBuild -ge 19042) {
    $DisplayVersion = $WindowsInfo.DisplayVersion
} else {
    $DisplayVersion = $WindowsInfo.ReleaseId
}
$ReleaseId = $DisplayVersion
if ($CurrentBuild -ge 22000) {
    $osPVersion = "Windows 11"
} else {
    $osPVersion = "Windows 10"
}

Write-Host $WindowsCaption $osArch -ForegroundColor White -BackgroundColor DarkGreen
Write-Host "目前版本為:" $DisplayVersion Build $CurrentBuild`.$CurrentUBR -ForegroundColor White -BackgroundColor DarkGreen
try {
    if (($ProductSetting = (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ProductVersion' -ea SilentlyContinue)) -ne $null) {
        $ProductSetting = "$ProductSetting "
    } else {
        $ProductSetting = ""
    }
}
catch {
    $ProductSetting = ""
}
try {
    if (($CurrentSetting = (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersionInfo' -ea SilentlyContinue)) -ne $null) {
        Write-Host "目前已設定版本(target release version)為:" [$ProductSetting$CurrentSetting] -ForegroundColor Black -BackgroundColor Yellow
    } else {
        Write-Host "目前無設定版本(target release version)" -ForegroundColor Black -BackgroundColor Yellow
    }
}
catch {
    Write-Host "目前無設定版本(target release version)" -ForegroundColor Black -BackgroundColor Yellow
}
$InputReleaseId = Read-Host -Prompt 輸入要設定的版本`(target` release` version`)[要清空既有設定_輸入0][$ReleaseId]
if ($InputReleaseId) {
    $ReleaseId = $InputReleaseId
}
if ($ReleaseId -ne 0) {
    $go = Read-Host -Prompt 確定要設定版本為[$ReleaseId]?" (Y/N)"
    if (($go -eq "Y") -or ($go -eq "y")) {
        if ((Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -force -ea SilentlyContinue > $null 2>&1 }
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersion' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue > $null 2>&1
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersionInfo' -Value $ReleaseId -PropertyType String -Force -ea SilentlyContinue > $null 2>&1
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ProductVersion' -Value $osPVersion -PropertyType String -Force -ea SilentlyContinue > $null 2>&1
    
        if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersionInfo' -ea SilentlyContinue) -eq $ReleaseId) {
            Write-Host 設定版本為[$osPVersion $ReleaseId] 完成 -ForegroundColor White -BackgroundColor DarkGreen
        } else {
            Write-Host 設定版本為[$osPVersion $ReleaseId] 失敗 -ForegroundColor White -BackgroundColor DarkRed
        }
    }
} else {
    $go = Read-Host -Prompt 確定要清空既有設定版本?" (Y/N)"
    if (($go -eq "Y") -or ($go -eq "y")) {
        if (((Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ea SilentlyContinue).property) -contains 'TargetReleaseVersion') {
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersion' -Force -ea SilentlyContinue > $null 2>&1
        }
        if (((Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ea SilentlyContinue).property) -contains 'TargetReleaseVersionInfo') {
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'TargetReleaseVersionInfo' -Force -ea SilentlyContinue > $null 2>&1
        }
        if (((Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ea SilentlyContinue).property) -contains 'ProductVersion') {
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ProductVersion' -Force -ea SilentlyContinue > $null 2>&1
        }
        if ((Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate") -and ((Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ea SilentlyContinue).property.count -eq 0)) {
            Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Force -ea SilentlyContinue > $null 2>&1
        }

        if ((((Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ea SilentlyContinue).property) -notcontains 'TargetReleaseVersion') -and (((Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ea SilentlyContinue).property) -notcontains 'TargetReleaseVersionInfo')) {
            Write-Host 清空既有設定版本 完成 -ForegroundColor White -BackgroundColor DarkGreen
        } else {
            Write-Host 清空既有設定版本 失敗 -ForegroundColor White -BackgroundColor DarkRed
        }
    }
}

pause
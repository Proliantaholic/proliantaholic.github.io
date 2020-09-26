###########################################################
#  By Proliantaholic https://proliantaholic.blogspot.com  #
###########################################################

# Elevate Powershell to Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

# Check WinUserLanguageList for zh-Hant-TW
$i = 0
while ((Get-WinUserLanguageList)[$i].LanguageTag -ne "zh-Hant-TW")
{
    $i++
}

# Add ChangJie and Quick IME
Write-Host "Add ChangJie and Quick IME..." -ForegroundColor Black -BackgroundColor Green
$UserLanguageList = Get-WinUserLanguageList
$UserLanguageList[$i].InputMethodTips.Add("0404:{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}{4BDF9F03-C7D3-11D4-B2AB-0080C882687E}")
$UserLanguageList[$i].InputMethodTips.Add("0404:{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}{6024B45F-5C54-11D4-B921-0080C882687E}")
Set-WinUserLanguageList -LanguageList $UserLanguageList -Force

# Set "Use previous version of" Microsoft Bopomofo, ChangJie and Quick IME (Windows 10 20H1 and above)
if ([System.Environment]::OSVersion.Version.Build -ge 19041) {
    Write-Host "Set [Use previous version of] Microsoft Bopomofo, ChangJie and Quick IME (Windows 10 20H1 and above)..." -ForegroundColor Black -BackgroundColor Green
    Write-Host "OS Version:" -NoNewline
    [System.Environment]::OSVersion.Version
    if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Input\TSF\Tsf3Override\{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Input\TSF\Tsf3Override\{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Input\TSF\Tsf3Override\{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}\{4BDF9F03-C7D3-11D4-B2AB-0080C882687E}") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Input\TSF\Tsf3Override\{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}\{4BDF9F03-C7D3-11D4-B2AB-0080C882687E}" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Input\TSF\Tsf3Override\{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}\{6024B45F-5C54-11D4-B921-0080C882687E}") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Input\TSF\Tsf3Override\{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}\{6024B45F-5C54-11D4-B921-0080C882687E}" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Input\TSF\Tsf3Override\{B115690A-EA02-48D5-A231-E3578D2FDF80}") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Input\TSF\Tsf3Override\{B115690A-EA02-48D5-A231-E3578D2FDF80}" -force -ea SilentlyContinue };
    New-ItemProperty -LiteralPath "HKCU:\SOFTWARE\Microsoft\Input\TSF\Tsf3Override\{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}\{4BDF9F03-C7D3-11D4-B2AB-0080C882687E}" -Name "NoTsf3Override2" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKCU:\SOFTWARE\Microsoft\Input\TSF\Tsf3Override\{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}\{6024B45F-5C54-11D4-B921-0080C882687E}" -Name "NoTsf3Override2" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKCU:\SOFTWARE\Microsoft\Input\TSF\Tsf3Override\{B115690A-EA02-48D5-A231-E3578D2FDF80}" -Name "NoTsf3Override4" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
}

# Set Registry for adding New ChangJie and New Quick IME
Write-Host "Set Registry for adding New ChangJie and New Quick IME..." -ForegroundColor Black -BackgroundColor Green
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{F3BA907A-6C7E-11D4-97FA-0080C882687E}") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{F3BA907A-6C7E-11D4-97FA-0080C882687E}" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{0B883BA0-C1C7-11D4-87F9-0080C882687E}") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{0B883BA0-C1C7-11D4-87F9-0080C882687E}" -force -ea SilentlyContinue };
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{F3BA907A-6C7E-11D4-97FA-0080C882687E}" -Name "Description" -Value "Microsoft New ChangJie" -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{F3BA907A-6C7E-11D4-97FA-0080C882687E}" -Name "Display Description" -Value "@%SystemRoot%\SYSTEM32\input.dll,-5093" -PropertyType ExpandString -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{F3BA907A-6C7E-11D4-97FA-0080C882687E}" -Name "IconFile" -Value "%SystemRoot%\system32\IME\IMETC\ImTCTip.DLL" -PropertyType ExpandString -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{F3BA907A-6C7E-11D4-97FA-0080C882687E}" -Name "IconIndex" -Value 2 -PropertyType DWord -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{F3BA907A-6C7E-11D4-97FA-0080C882687E}" -Name "Enable" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{F3BA907A-6C7E-11D4-97FA-0080C882687E}" -Name "ProfileFlags" -Value 4 -PropertyType DWord -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{0B883BA0-C1C7-11D4-87F9-0080C882687E}" -Name "Description" -Value "Microsoft New Quick" -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{0B883BA0-C1C7-11D4-87F9-0080C882687E}" -Name "Display Description" -Value "@%SystemRoot%\SYSTEM32\input.dll,-5149" -PropertyType ExpandString -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{0B883BA0-C1C7-11D4-87F9-0080C882687E}" -Name "IconFile" -Value "%SystemRoot%\system32\IME\IMETC\ImTCTip.DLL" -PropertyType ExpandString -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{0B883BA0-C1C7-11D4-87F9-0080C882687E}" -Name "IconIndex" -Value 4 -PropertyType DWord -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{0B883BA0-C1C7-11D4-87F9-0080C882687E}" -Name "Enable" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\CTF\TIP\{B115690A-EA02-48D5-A231-E3578D2FDF80}\LanguageProfile\0x00000404\{0B883BA0-C1C7-11D4-87F9-0080C882687E}" -Name "ProfileFlags" -Value 4 -PropertyType DWord -Force -ea SilentlyContinue;

#Remove old IME (ChangJie and Quick)
Write-Host "Remove old IME (ChangJie and Quick)..." -ForegroundColor Black -BackgroundColor Green
$UserLanguageList = Get-WinUserLanguageList
$UserLanguageList[$i].InputMethodTips.Remove("0404:{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}{4BDF9F03-C7D3-11D4-B2AB-0080C882687E}")
$UserLanguageList[$i].InputMethodTips.Remove("0404:{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}{6024B45F-5C54-11D4-B921-0080C882687E}")
Set-WinUserLanguageList -LanguageList $UserLanguageList -Force

# Add New ChangJie and New Quick IME
powershell {
    $j = 0
    while ((Get-WinUserLanguageList)[$j].LanguageTag -ne "zh-Hant-TW")
    {
        $j++
    }
    $UserLanguageList = Get-WinUserLanguageList
    $UserLanguageList[$j].InputMethodTips.Add("0404:{B115690A-EA02-48D5-A231-E3578D2FDF80}{F3BA907A-6C7E-11D4-97FA-0080C882687E}")
    $UserLanguageList[$j].InputMethodTips.Add("0404:{B115690A-EA02-48D5-A231-E3578D2FDF80}{0B883BA0-C1C7-11D4-87F9-0080C882687E}")
    Set-WinUserLanguageList -LanguageList $UserLanguageList -Force
}
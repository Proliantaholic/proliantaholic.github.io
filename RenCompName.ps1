Write-Host "目前電腦名稱:" $env:computername
$NewComputerName=Read-Host -Prompt "輸入新的電腦名稱"
$Go=Read-Host -prompt "確定要更改電腦名稱? (Y/N)"
If(($Go -eq "Y") -or ($Go -eq "y"))
{
Rename-Computer -NewName $NewComputerName -PassThru
}
#Requires -Version 7
#Requires -RunAsAdministrator

param (
    [Parameter(Mandatory)][String]$nsudo,
    [Parameter(Mandatory)][String]$path,
    [Parameter(Mandatory)][String]$input_file,
    [Parameter(Mandatory)][UInt32]$index,
    [Parameter(Mandatory)][String]$output_file,
    [Parameter(Mandatory)][String]$compression,
    [Parameter(Mandatory)][String]$name
)

$ErrorActionPreference = 'Stop'
[System.Runtime.InteropServices.NativeLibrary]::Load($nsudo)

# Expand-WindowsImage
if ($input_file -ne 'nul') {
    if ((Split-Path -NoQualifier $path) -eq '\') {
        Format-Volume $path[0]
    }
    Expand-WindowsImage -ImagePath $input_file -Index $index -ApplyPath $path
}
Push-Location "$PSScriptRoot\..\data"

# Set-WindowsProductKey
if (
    Get-WindowsEdition -Path $path |
        Where-Object Edition -CNotIn ProfessionalWorkstation, ServerStandard
) {
    Set-WindowsProductKey -ProductKey DXG7C-N36C4-C4HTG-X4T3X-2YV77 -Path $path
}

# AppxProvisionedPackage
# MS Office should be installed via dism /OptionalPackagePath
Get-AppxProvisionedPackage -Path $path |
    Where-Object DisplayName -CNotIn Microsoft.DesktopAppInstaller,
        Microsoft.SecHealthUI |
    Sort-Object DisplayName |
    Out-GridView -Title Remove-AppxProvisionedPackage -PassThru |
    Remove-AppxProvisionedPackage

Get-AppxProvisionedPackage -Path $path |
    Sort-Object DisplayName |
    Out-GridView -Title 'Appx Installed'

Get-ChildItem -Exclude Microsoft.Office.Desktop* appx |
    ForEach-Object Name |
    Out-GridView -Title Add-AppxProvisionedPackage -PassThru |
    Select-Object @{label='PackagePath'; expression={"appx\$_"}} |
    Add-AppxProvisionedPackage -SkipLicense -Path $path

# WindowsCapability
Get-WindowsCapability -Path $path |
    Where-Object State -CEQ Installed |
    Where-Object Name -CNotIn Browser.InternetExplorer~~~~0.0.11.0,
        DirectX.Configuration.Database~~~~0.0.1.0,
        Edge.Webview2.Platform~~~~,
        Language.Basic~~~zh-CN~0.0.1.0,
        Language.Fonts.Hans~~~und-HANS~0.0.1.0,
        Language.Handwriting~~~zh-CN~0.0.1.0,
        Language.OCR~~~zh-CN~0.0.1.0,
        Language.Speech~~~zh-CN~0.0.1.0,
        Language.TextToSpeech~~~zh-CN~0.0.1.0,
        Microsoft.Windows.Sense.Client~~~~,
        Windows.HyperV.OptionalFeature.VirtualMachinePlatform.Client.Disabled~~~~,
        Windows.Kernel.LA57~~~~0.0.1.0,
        Windows.SmbDirect~~~~,
        Windows.WinOcr~~~~,
        Windows.WorkFolders.Client~~~~,
        WMIC~~~~ |
    Out-GridView -Title Remove-WindowsCapability -PassThru |
    Remove-WindowsCapability

# WindowsOptionalFeature
# Enable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM,
#     VirtualMachinePlatform -Path $path

Get-WindowsOptionalFeature -Path $path |
    Where-Object State -CEQ Enabled |
    Where-Object FeatureName -CNotIn Containers-DisposableClientVM,
        Microsoft-Windows-Printing-PremiumTools,
        MicrosoftWindowsPowerShell,
        MicrosoftWindowsPowerShellRoot,
        NetFx4,
        NetFx4ServerFeatures,
        Printing-PrintToPDFServices-Features,
        Server-Core,
        Server-Drivers-General,
        Server-Drivers-Printers,
        Server-Gui-Mgmt,
        Server-Psh-Cmdlets,
        Server-Shell,
        ServerCore-Drivers-General,
        ServerCore-Drivers-General-WOW64,
        ServerCore-WOW64,
        ServerCoreFonts-NonCritical-Fonts-BitmapFonts,
        ServerCoreFonts-NonCritical-Fonts-MinConsoleFonts,
        ServerCoreFonts-NonCritical-Fonts-Support,
        ServerCoreFonts-NonCritical-Fonts-TrueType,
        ServerCoreFonts-NonCritical-Fonts-UAPFonts,
        VirtualMachinePlatform,
        WirelessNetworking |
    Sort-Object FeatureName |
    Out-GridView -Title Disable-WindowsOptionalFeature -PassThru |
    Disable-WindowsOptionalFeature

# AppAssociations
Dism.exe /Image:$path /Remove-DefaultAppAssociations
Dism.exe /Image:$path /Import-DefaultAppAssociations:AppAssoc.xml

# Files
Copy-Item -Force fonts\* $path\Windows\Fonts
Copy-Item -Force hosts $path\Windows\System32\drivers\etc

# Repair-WindowsImage
Pop-Location
Repair-WindowsImage -StartComponentCleanup -ResetBase -Path $path
if ($output_file -ne 'nul') {
    New-WindowsImage -ImagePath $output_file -CapturePath $path `
        -CompressionType $compression -Description $name -Name $name
}

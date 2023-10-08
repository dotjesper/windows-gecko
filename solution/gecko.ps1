<# PSScriptInfo
.VERSION 0.9.9.9
.GUID 8A7803A1-6E81-4863-8600-F9A105DFD640
.AUTHOR @dotjesper
.COMPANYNAME dotjesper.com
.COPYRIGHT dotjesper.com
.TAGS windows powershell windows-10 branding microsoft-intune windows-11 windows-autopilot endpoint-management
.LICENSEURI https://github.com/dotjesper/windows-gecko/blob/main/LICENSE
.PROJECTURI https://github.com/dotjesper/windows-gecko
.ICONURI
.EXTERNALSCRIPTDEPENDENCIES
.REQUIREDSCRIPTS
.RELEASENOTES https://github.com/dotjesper/windows-gecko/wiki/release-notes
#>
<#
.SYNOPSIS
    Windows Desired State Configuration - baseline configuration
.DESCRIPTION
    The goal of Windows gecko is to provide a consistent desired state configuration to end user devices in Windows Autopilot scenarios.
    Windows gecko can easily be implemented using more traditionally deployment methods, like OSD or other methods utilized.
    Current features:
    - WindowsApps: Remove Windows In-box Apps and Store Apps.
    - WindowsBranding: Configure OEM information and Registration (Coming soon)
    - WindowsFeatures
        - Enable and/or disable Windows features.
        - Enable and/or disable Windows optional features.
    - WindowsGroups: Add accounts to local groups (Coming soon).
    - WindowsFiles: Copy file(s) to device from payload package.
    - WindowsRegistry: Modifying Windows registry entries (add, change and remove).
    - WindowsRun: Run local executables and/or download and run executables.
    - WindowsServices: Configure/re-configure Windows Services.
    - WindowsTCR: Windows Time zone, Culture and Regional settings manager (PREVIEW).
    To download sample configuration files and follow the latest progress, visit the project site.
    ---------------------------------------------------------------------------------
    LEGAL DISCLAIMER
    The PowerShell script provided is shared with the community as-is. The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability,
    or suitability for any specific purpose. Please note that the script may need to be modified or adapted to fit your specific environment or requirements.
    It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system. The author and co-author(s) cannot be held
    responsible for any damages, losses, or adverse effects that may arise from the use of this script. You assume all risks and responsibilities associated with its usage.
    ---------------------------------------------------------------------------------
.PARAMETER configFile
    Start script with the defined configuration file to be used for the task.
    If no configuration file is defined, script will look for .\config.json. If the configuration is not found or invalid, the script will exit.
.PARAMETER CID
    Windows Time zone, culture and regional settings value, allowing configuring culture, homelocation, and timezone from configuration file.
    Value must match windowsTCR.configuration.[CID], e.g. "da-DK", "565652" or similar. See sample files for examples.
.PARAMETER logFile
    Start script logging to the desired logfile.
    If no log file is defined, the script will default to log file within '%ProgramData%\Microsoft\IntuneManagementExtension\Logs' folder, file name <config.metadata.title>.log
.PARAMETER exitOnError
    If an error occurs, control if script should exit-on-error. Default value is $false.
.PARAMETER runSilent
    Set ProgressPreference to SilentlyContinue, hiding powershell progress bars. Default value is $true.
.PARAMETER uninstall
    Future parameter for use in Micrsoft Intune package deployment scenarios. Default value is $false.
.EXAMPLE
    .\gecko.ps1
.EXAMPLE
    .\gecko.ps1 -configFile ".\usercfg.json"
.EXAMPLE
    .\gecko.ps1 -configFile ".\usercfg.json" -CID "da-DK"
.EXAMPLE
    .\gecko.ps1 -configFile ".\usercfg.json" -logFile ".\usercfg.log" -Verbose
#>
#requires -version 5.1
[CmdletBinding()]
param (
    #variables
    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ })]
    [string]$configFile = ".\config.json",
    [Parameter(Mandatory = $false)]
    [string]$CID,
    [Parameter(Mandatory = $false)]
    [string]$logFile = "",
    [Parameter(Mandatory = $false)]
    [switch]$exitOnError,
    [Parameter(Mandatory = $false)]
    [bool]$runSilent = $true,
    [Parameter(Mandatory = $false)]
    [switch]$uninstall
)
begin {
    #region :: environment
    #
    #endregion
    #region :: configuation file
    if (Test-Path -Path $configFile -PathType Leaf) {
        try {
            $config = Get-Content -Path $configFile -Raw
            $config = ConvertFrom-Json -InputObject $config
        }
        catch {
            Write-Output -InputObject "Error reading [$configFile], script exiting."
            throw $_.Exception.Message
            exit 1
        }
    }
    else {
        Write-Output -InputObject "Cannot read [$configFile] - file not found, script exiting."
        Write-Output -InputObject "> Go to https://github.com/dotjesper/windows-gecko/ to download sample configuration files."
        exit 1
    }
    #endregion
    #region :: environment configurations
    [bool]$requireReboot = $($config.runConditions.requireReboot)
    [string]$envProgressPreference = $ProgressPreference
    [string]$envWarningPreference = $WarningPreference
    if ($runSilent) {
        $ProgressPreference = "SilentlyContinue"
        $WarningPreference = "SilentlyContinue"
    }
    #endregion
    #region :: logfile
    if ($($config.metadata.title)) {
        [string]$fLogContentpkg = "$($config.metadata.title -replace '[^a-zA-Z0-9]','-')"
        [string]$fLogContentFile = "$($Env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\$fLogContentpkg.log"
    }
    else {
        [string]$fLogContentpkg = "$(([io.fileinfo]$MyInvocation.MyCommand.Definition).BaseName -replace '[^a-zA-Z0-9]','-')"
        [string]$fLogContentFile = "$($Env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\$fLogContentpkg.log"
    }
    if ($logfile.Length -gt 0) {
        $logfileFullPath = Resolve-Path $logfile -ErrorAction SilentlyContinue -ErrorVariable _frperror
        if ($logfileFullPath) {
            [string]$fLogContentFile = $logfileFullPath
        }
        else {
            [string]$fLogContentFile = $_frperror[0].TargetObject
        }
    }
    #
    try {
        $fileChk = $(New-Object -TypeName System.IO.FileInfo -ArgumentList $($fLogContentFile)).OpenWrite();
        Write-Verbose -Message "$fLogContentFile is writeable: $($fileChk.CanWrite)"
        $fileChk.Close();
    }
    catch {
        $fLogContentDisable = $true
        Write-Warning -Message "Unable to write to output file $fLogContentFile"
        Write-Verbose -Message $_.Exception.Message
        Write-Verbose -Message "Redireting output file to '$($Env:Temp)' folder"
        [string]$fLogContentFile = "$($Env:Temp)\$fLogContentpkg.log"
    }
    finally {}
    #endregion
    #
    #region :: functions
    function fLogContent () {
        <#
        .SYNOPSIS
           Log-file function.
        .DESCRIPTION
            Log-file function, write a single log line when called.
            Each line in the log can have various attributes, log text, information about the component from which the fumction is called and an option to specify log file name for each entry.
            Formatting adhere to the CMTrace and Microsoft Intune log format.
        .PARAMETER fLogContent
            Holds the string to write to the log file. If script is called with the -Verbose, this string will be sent to the console.
        .PARAMETER fLogContentComponent
            Information about the component from which the fumction is called, e.g. a specific section in the script.
        .PARAMETER fLogContentType
            Standard log types
			1: MessageTypeInfo - Informational Message (Default)
			2: MessageTypeWarning - Warning Message
			3: MessageTypeError - Error Message
        .PARAMETER fLogContentfn
            Option to specify log file name for each entry.
        .EXAMPLE
            fLogContent -fLogContent "This is the log string." -fLogContentComponent "If applicable, add section, or component for log entry."
        #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$fLogContent,
            [Parameter(Mandatory = $false)]
            [string]$fLogContentComponent,
            [Parameter(Mandatory = $false)]
            [ValidateSet(1,2,3)]
            [int]$fLogContentType = 1,
            [Parameter(Mandatory = $false)]
            [string]$fLogContentfn = $fLogContentFile
        )
        begin {
            $fdate = $(Get-Date -Format "M-dd-yyyy")
            $ftime = $(Get-Date -Format "HH:mm:ss.fffffff")
        }
        process {
            if ($fLogContentDisable) {

            }
            else {
                try {
                    if (-not (Test-Path -Path "$(Split-Path -Path $fLogContentfn)")) {
                        New-Item -itemType "Directory" -Path "$(Split-Path -Path $fLogContentfn)" | Out-Null
                    }
                    Add-Content -Path $fLogContentfn -Value "<![LOG[[$fLogContentpkg] $($fLogContent)]LOG]!><time=""$($ftime)"" date=""$($fdate)"" component=""$fLogContentComponent"" context="""" type=""$fLogContentType"" thread="""" file="""">" -Encoding "UTF8" | Out-Null
                }
                catch {
                    throw $_.Exception.Message
                    exit 1
                }
                finally {}
            }
            Write-Verbose -Message "$($fLogContent)"
        }
        end {}
    }
    function fRegistryItem () {
        <#
        .SYNOPSIS
            Windows registry function.
        .DESCRIPTION
            This function is used to modify Windows registry entries (add, update or remove).
        .PARAMETER task
            Parameter will determine if funtion should ADD (Update) or REMOVE the entry defines using the 'froot':\'fpath' fname and fvalue parameters.
        .PARAMETER froot
            Parameter will define registry root, valid values: HKCR, HKCU, HKLM.
        .PARAMETER fpath
            Parameter for assigning registry path, e.g. 'Software\Microsoft\Windows\CurrentVersion'.
        .PARAMETER fname
            Parameter for assigning registry name, e.g. 'sample'.
        .PARAMETER fpropertyType
            Parameter for assigning property type, e.g. 'String', 'DWord' etc.
        .PARAMETER fvalue
            Parameter for assigning registry value.
        .EXAMPLE
            fRegistryItem -task "add" -froot "HKLM" -fpath "Software\Microsoft\Windows\CurrentVersion" -fname "Sample" -fpropertyType "DWORD" -fvalue "1"
        #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$task,
            [Parameter(Mandatory = $true)]
            [string]$froot,
            [Parameter(Mandatory = $true)]
            [string]$fpath,
            [Parameter(Mandatory = $true)]
            [string]$fname,
            [Parameter(Mandatory = $true)]
            [string]$fpropertyType,
            [Parameter(Mandatory = $false)]
            [string]$fvalue
        )
        begin {
            switch ($fpropertyType) {
                "REG_SZ" {
                    $fpropertyType = "String"
                }
                "REG_EXPAND_SZ" {
                    $fpropertyType = "ExpandString"
                }
                "REG_BINARY" {
                    $fpropertyType = "Binary"
                }
                "REG_DWORD" {
                    $fpropertyType = "DWord"
                }
                "REG_MULTI_SZ" {
                    $fpropertyType = "MultiString"
                }
                "REG_QWOR" {
                    $fpropertyType = "Qword"
                }
                "REG_RESOURCE_LIST" {
                    $fpropertyType = "Unknown"
                }
                Default {}
            }
            if ($($(Get-PSDrive -PSProvider "Registry" -Name "$froot" -ErrorAction "SilentlyContinue").Name)) {
                fLogContent -fLogContent "registry PSDrive $($froot) exists." -fLogContentComponent "fRegistryItem"
            }
            else {
                switch ("$froot") {
                    "HKCR" {
                        fLogContent -fLogContent "registry PSDrive $($froot) not found, creating PSDrive." -fLogContentComponent "fRegistryItem"
                        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Scope "Script" -Verbose:$false | Out-Null
                    }
                    "HKCU" {
                        fLogContent -fLogContent "registry PSDrive $($froot) not found, creating PSDrive." -fLogContentComponent "fRegistryItem"
                        New-PSDrive -Name "HKCU" -PSProvider "Registry" -Root "HKEY_CURRENT_USER" -Scope "Script" -Verbose:$false | Out-Null
                    }
                    "HKLM" {
                        fLogContent -fLogContent "registry PSDrive $($froot) not found, creating PSDrive." -fLogContentComponent "fRegistryItem"
                        New-PSDrive -Name "HKLM" -PSProvider "Registry" -Root "HKEY_LOCAL_MACHINE" -Scope "Script" -Verbose:$false | Out-Null
                    }
                    Default {
                        fLogContent -fLogContent "registry PSDrive $($froot) has an unknown or unsupported value, exiting." -fLogContentComponent "fRegistryItem"
                        exit 1
                    }
                }
            }
        }
        process {
            switch ($task) {
                "add" {
                    try {
                        #Test Registry path exists and create if not found.
                        if (-not (Test-Path -Path "$($froot):\$($fpath)")) {
                            fLogContent -fLogContent "registry path [$($froot):\$($fpath)] not found." -fLogContentComponent "fRegistryItem"
                            try {
                                New-Item -Path "$($froot):\$($fpath)" -Force | Out-Null
                                fLogContent -fLogContent "registry path [$($froot):\$($fpath)] created." -fLogContentComponent "fRegistryItem"
                            }
                            catch {
                                $errMsg = $_.Exception.Message
                                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "fRegistryItem" -fLogContentType 3
                            }
                            finally {}
                        }
                        else {
                            fLogContent -fLogContent "registry path [$($froot):\$($fpath)] exists." -fLogContentComponent "fRegistryItem"
                        }
                        #Get current value if exist.
                        $fcurrentValue = $(Get-ItemProperty -path "$($froot):\$($fpath)" -name $fname -ErrorAction SilentlyContinue)."$fname"
                        if ($fcurrentValue -eq $fvalue) {
                            fLogContent -fLogContent "registry value already configured" -fLogContentComponent "fRegistryItem"
                        }
                        else {
                            fLogContent -fLogContent "registry value not found or different, forcing update: [$fpropertyType] $fname [ '$fcurrentValue' -> '$fvalue' ]" -fLogContentComponent "fRegistryItem"
                        }
                        #Adding registry item.
                        New-ItemProperty -Path "$($froot):\$($fpath)" -Name "$fname" -PropertyType "$fpropertyType" -Value "$fvalue" -Force | Out-Null
                        #Validating registry item.
                        $fcurrentValue = $(Get-ItemProperty -path "$($froot):\$($fpath)" -name $fname -ErrorAction SilentlyContinue)."$fname"
                        if ($fcurrentValue -eq $fvalue) {
                            fLogContent -fLogContent "registry value configuration succesfull [ '$fcurrentValue' ]" -fLogContentComponent "fRegistryItem"
                        }
                        else {
                            fLogContent -fLogContent "registry value configuration failed" -fLogContentComponent "fRegistryItem" -fLogContentType 3
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "fRegistryItem" -fLogContentType 3
                        exit 1
                    }
                    finally {}
                }
                "remove" {
                    try {
                        #Test if registry key exists and delete if found.
                        if (-not (Get-ItemPropertyValue -Path "$($froot):\$($fpath)" -Name "$fname" -ErrorAction "SilentlyContinue")) {
                            fLogContent -fLogContent "registry value [$($froot):\$($fpath)] : $($fname) not found." -fLogContentComponent "fRegistryItem"
                        }
                        else {
                            fLogContent -fLogContent "registry value [$($froot):\$($fpath)] : $($fname) found." -fLogContentComponent "fRegistryItem"
                            fLogContent -fLogContent "deleting registry value [$($froot):\$($fpath)] : $($fname)." -fLogContentComponent "fRegistryItem"
                            Remove-ItemProperty -Path "$($froot):\$($fpath)" -Name $($fname) -Force | Out-Null
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "fRegistryItem" -fLogContentType 3
                        exit 1
                    }
                    finally {}
                }
                Default {}
            }
        }
        end {}
    }
    #endregion
    #
    #region :: logfile environment entries
    try {
        fLogContent -fLogContent "## $($config.metadata.title) by $($config.metadata.developer)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Config file: $($configFile)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Config file version: $($config.metadata.version) | $($config.metadata.date)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Config file description: $($config.metadata.description)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Log file: $($fLogContentFile)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Script name: $($MyInvocation.MyCommand.Name)" -fLogContentComponent "environment"
       #fLogContent -fLogContent "Command line: $($MyInvocation.Line)" -fLogContentComponent "environment"
        foreach ($key in $MyInvocation.BoundParameters.keys) {
            switch ($MyInvocation.BoundParameters[$key].GetType().Name) {
                "Boolean" {
                    $argsString += "-$key `$$($MyInvocation.BoundParameters[$key]) "
                }
                "Int32" {
                    $argsString += "-$key $($MyInvocation.BoundParameters[$key]) "
                }
                "String" {
                    $argsString += "-$key `"$($MyInvocation.BoundParameters[$key])`" "
                }
                "SwitchParameter" {
                    if ($MyInvocation.BoundParameters[$key].IsPresent) {
                        $argsString += "-$key "
                    }
                }
                Default {}
            }
        }
        fLogContent -fLogContent "Command line: .\$($myInvocation.myCommand.name) $($argsString)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Run script in 64 bit PowerShell: $($config.runConditions.runScriptIn64bitPowerShell)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Running 64 bit PowerShell: $([System.Environment]::Is64BitProcess)" -fLogContentComponent "environment"
        if ($($ExecutionContext.SessionState.LanguageMode) -eq "FullLanguage") {
            fLogContent -fLogContent "Running elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" -fLogContentComponent "environment"
            fLogContent -fLogContent "Detected user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -fLogContentComponent "environment"
        }
        else {
            fLogContent -fLogContent "Detected user: $($Env:USERNAME)" -fLogContentComponent "environment"
        }
        fLogContent -fLogContent "Detected keyboard layout Id: $((Get-Culture).KeyboardLayoutId)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Detected language mode: $($ExecutionContext.SessionState.LanguageMode)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Detected culture name: $((Get-Culture).Name)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Detected OS build: $($([environment]::OSVersion.Version).Build)" -fLogContentComponent "environment"
    }
    catch {
        $errMsg = $_.Exception.Message
        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "environment" -fLogContentType 3
        if ($exitOnError) {
            exit 1
        }
    }
    finally {}
    #endregion
    #
    #region :: check conditions
    if ($($config.runConditions.runScriptIn64bitPowerShell) -eq $true -and $([System.Environment]::Is64BitProcess) -eq $false) {
        fLogContent -fLogContent "Script must be run using 64-bit PowerShell." -fLogContentComponent "environment"
        try {
            fLogContent -fLogContent "Script relaunching using 64-bit PowerShell." -fLogContentComponent "environment"
           #fLogContent -fLogContent $("Command line: .\" + $($myInvocation.myCommand.name) + " " + $($argsString)) -fLogContentComponent "environment"
            Start-Process -FilePath "$env:windir\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList $("-ExecutionPolicy Bypass -File .\" + $($myInvocation.myCommand.name) + " " + $($argsString)) -Wait -NoNewWindow
            exit 0
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "environment" -fLogContentType 3
            if ($exitOnError) {
                exit 1
            }
        }
    }
    #endregion
}
process {
    #region :: windowsApps
    fLogContent -fLogContent "WINDOWS APPS" -fLogContentComponent "windowsApps"
    if ($($config.windowsApps.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Apps is enabled." -fLogContentComponent "windowsApps"
        [array]$windowsApps = $($config.windowsApps.apps)
        foreach ($windowsApp in $windowsApps) {
            fLogContent -fLogContent "Processing $($windowsApp.DisplayName)." -fLogContentComponent "windowsApps"
            #region :: Appx Package
            try {
                [array]$AppxPackage = Get-AppxPackage -AllUsers -Name $($windowsApp.Name) -Verbose:$false
                if ($AppxPackage) {
                    fLogContent -fLogContent "$($windowsApp.DisplayName) is present." -fLogContentComponent "windowsApps"
                    fLogContent -fLogContent "$($windowsApp.DisplayName) is bundle: $($AppxPackage.IsBundle)." -fLogContentComponent "windowsApps"
                    fLogContent -fLogContent "$($windowsApp.DisplayName) is non-removable: $($AppxPackage.NonRemovable)." -fLogContentComponent "windowsApps"
                    if ($($windowsApp.Remove) -eq $true) {
                        fLogContent -fLogContent "$($windowsApp.DisplayName) is being removed from all users." -fLogContentComponent "windowsApps"
                        fLogContent -fLogContent "$($windowsApp.DisplayName) :: $($AppxPackage.Name)." -fLogContentComponent "windowsApps"
                        fLogContent -fLogContent "$($windowsApp.DisplayName) :: $($AppxPackage.PackageFullName)." -fLogContentComponent "windowsApps"
                        fLogContent -fLogContent "$($windowsApp.DisplayName) :: $($AppxPackage.PackageFamilyName)." -fLogContentComponent "windowsApps"
                        fLogContent -fLogContent "$($windowsApp.DisplayName) :: $($AppxPackage.Version)." -fLogContentComponent "windowsApps"
                        try {
                            Remove-AppxPackage -AllUsers -Package "$($AppxPackage.PackageFullName)" -Verbose:$false | Out-Null
                            #Get-AppxPackage -PackageTypeFilter Main, Bundle, Resource | Where-Object {$_.PackageFullName -eq "$($AppxPackage.PackageFullName)"} | Remove-AppxPackage -Allusers -Verbose:$false
                        }
                        catch {
                            $errMsg = $_.Exception.Message
                            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsApps" -fLogContentType 3
                            if ($exitOnError) {
                                exit 1
                            }
                        }
                        finally {}
                    }
                }
                else {
                    fLogContent -fLogContent "$($windowsApp.Name) not present." -fLogContentComponent "windowsApps"
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsApps" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
            #endregion
            #region :: Appx Provisioned Package
            try {
                [array]$AppxProvisionedPackage = Get-AppxProvisionedPackage -Online -Verbose:$false | Where-Object { $_.DisplayName -eq $($windowsApp.Name) } | Select-Object "DisplayName", "Version", "PublisherId", "PackageName"
                if ($AppxProvisionedPackage) {
                    fLogContent -fLogContent "$($windowsApp.DisplayName) is present as provisioned app." -fLogContentComponent "windowsProvisionedApps"
                    fLogContent -fLogContent "$($windowsApp.DisplayName), $($AppxProvisionedPackage.DisplayName)." -fLogContentComponent "windowsProvisionedApps"
                    fLogContent -fLogContent "$($windowsApp.DisplayName), $($AppxProvisionedPackage.PackageName), $($AppxProvisionedPackage.Version)." -fLogContentComponent "windowsProvisionedApps"
                    fLogContent -fLogContent "$($windowsApp.DisplayName) remove: $($windowsApp.RemoveProvisionedPackage)." -fLogContentComponent "windowsProvisionedApps"
                    if ($($windowsApp.RemoveProvisionedPackage) -eq $true) {
                        fLogContent -fLogContent "$($AppxProvisionedPackage.DisplayName) is being removed." -fLogContentComponent "windowsProvisionedApps"
                        try {
                            Remove-AppxProvisionedPackage -Online -PackageName "$($AppxProvisionedPackage.PackageName)" -Verbose:$false | Out-Null
                        }
                        catch {
                            $errMsg = $_.Exception.Message
                            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsProvisionedApps" -fLogContentType 3
                            if ($exitOnError) {
                                exit 1
                            }
                        }
                        finally {}
                    }
                }
                else {
                    fLogContent -fLogContent "$($windowsApp.DisplayName) is not present." -fLogContentComponent "windowsProvisionedApps"
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsProvisionedApps" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
            #endregion
        }
        fLogContent -fLogContent "Windows Apps finished." -fLogContentComponent "windowsApps"
    }
    else {
        fLogContent -fLogContent "Windows Apps is disabled." -fLogContentComponent "windowsApps"
    }
    #endregion
    #
    #region: windowsBranding - PREVIEW
    ## windowsBranding is coming soon ##
    #endregion
    #
    #region :: windowsFeatures
    fLogContent -fLogContent "WINDOWS FEATURES" -fLogContentComponent "windowsFeatures"
    if ($($config.windowsFeatures.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Features is enabled." -fLogContentComponent "windowsFeatures"
        #region :: windowsFeatures
        [array]$windowsFeatures = $($config.windowsFeatures.features)
        foreach ($windowsFeature in $windowsFeatures) {
            fLogContent -fLogContent "Processing $($windowsFeature.DisplayName)." -fLogContentComponent "windowsFeatures"
            try {
                [string]$featureState = $(Get-WindowsOptionalFeature -Online -FeatureName $($windowsFeature.FeatureName) -Verbose:$false).state
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsFeatures" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
            if ($($windowsFeature.State) -eq $featureState) {
                fLogContent -fLogContent "$($windowsFeature.DisplayName) configured [$($windowsFeature.State)]." -fLogContentComponent "windowsFeatures"
            }
            else {
                fLogContent -fLogContent "configuring $($windowsFeature.DisplayName) [$($windowsFeature.State)]" -fLogContentComponent "windowsFeatures"
                try {
                    switch ($($windowsFeature.State).ToUpper()) {
                        "ENABLED" {
                            fLogContent -fLogContent "enabling $($windowsFeature.DisplayName)." -fLogContentComponent "windowsFeatures"
                            $windowsFeatureResult = Enable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -All -NoRestart -Verbose:$false | Out-Null
                            if ($windowsFeatureResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished enabling $($windowsFeature.DisplayName). Restart needed: $($windowsFeatureResult.RestartNeeded)" -fLogContentComponent "windowsFeatures"
                        }
                        "DISABLED" {
                            fLogContent -fLogContent "disabling $($windowsFeature.DisplayName)." -fLogContentComponent "windowsFeatures"
                            $windowsFeatureResult = Disable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -NoRestart -Verbose:$false
                            if ($windowsFeatureResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished disabling $($windowsFeature.DisplayName). Restart needed: $($windowsFeatureResult.RestartNeeded)" -fLogContentComponent "windowsFeatures"
                        }
                        Default {
                            fLogContent -fLogContent "unsupported state $($windowsFeature.DisplayName) [$($windowsFeature.State)]." -fLogContentComponent "windowsFeatures"
                        }
                    }
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsFeatures" -fLogContentType 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
            }
        }
        #endregion
        #region :: windowsOptionalFeatures
        fLogContent -fLogContent "WINDOWS OPTIONAL FEATURES" -fLogContentComponent "windowsOptionalFeatures"
        [array]$windowsOptionalFeatures = $($config.windowsFeatures.optionalFeatures)
        foreach ($windowsOptionalFeature in $windowsOptionalFeatures) {
            fLogContent -fLogContent "Processing $($windowsOptionalFeature.DisplayName)." -fLogContentComponent "windowsOptionalFeatures"
            [string]$featureState = $(Get-WindowsCapability -Online -Name $($windowsOptionalFeature.Name) -Verbose:$false).state
            if ($($windowsOptionalFeature.State) -eq $featureState) {
                fLogContent -fLogContent "$($windowsOptionalFeature.DisplayName) configured [$($windowsOptionalFeature.State)]." -fLogContentComponent "windowsOptionalFeatures"
            }
            else {
                fLogContent -fLogContent "configuring $($windowsOptionalFeature.DisplayName) [$($windowsOptionalFeature.State)]" -fLogContentComponent "windowsOptionalFeatures"
                switch ($($windowsOptionalFeature.State).ToUpper()) {
                    "INSTALLED" {
                        fLogContent -fLogContent "installing $($windowsOptionalFeature.DisplayName)." -fLogContentComponent "windowsOptionalFeatures"
                        try {
                            $windowsCapabilityResult = Add-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false
                            if ($windowsCapabilityResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished installing $($windowsOptionalFeature.DisplayName), restart needed: $($windowsCapabilityResult.RestartNeeded)" -fLogContentComponent "windowsFeatures"
                        }
                        catch {
                            $errMsg = $_.Exception.Message
                            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsOptionalFeatures" -fLogContentType 3
                            if ($exitOnError) {
                                exit 1
                            }
                        }
                        finally {}
                    }
                    "NOTPRESENT" {
                        fLogContent -fLogContent "removing $($windowsOptionalFeature.DisplayName)." -fLogContentComponent "windowsOptionalFeatures"
                        try {
                            $windowsCapabilityResult = Remove-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false
                            if ($windowsCapabilityResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished removing $($windowsOptionalFeature.DisplayName), restart needed: $($windowsCapabilityResult.RestartNeeded)" -fLogContentComponent "windowsFeatures"
                        }
                        catch {
                            $errMsg = $_.Exception.Message
                            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsOptionalFeatures" -fLogContentType 3
                            if ($exitOnError) {
                                exit 1
                            }
                        }
                        finally {}
                    }
                    Default {
                        fLogContent -fLogContent "unsupported state $($windowsOptionalFeature.DisplayName) [$($windowsOptionalFeature.State)]." -fLogContentComponent "windowsOptionalFeatures"
                    }
                }
            }
        }
        #endregion
        fLogContent -fLogContent "Windows Features finished." -fLogContentComponent "windowsFeatures"
    }
    else {
        fLogContent -fLogContent "Windows Features is disabled." -fLogContentComponent "windowsFeatures"
    }
    #endregion
    #
    #region :: windowsFiles
    fLogContent -fLogContent "WINDOWS FILES" -fLogContentComponent "windowsFiles"
    if ($($config.windowsFiles.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Files is enabled." -fLogContentComponent "windowsFiles"
        #region :: Expand assets
        [string]$assetFile = $($config.windowsFiles.assetFile)
        if (Test-Path -Path $assetFile -PathType Leaf) {
            fLogContent -fLogContent "Windows Files found $assetFile." -fLogContentComponent "windowsFiles"
            fLogContent -fLogContent "Windows Files is expanding $((Get-Item $assetFile).FullName)." -fLogContentComponent "windowsFiles"
            try {
                Expand-Archive -Path "$assetFile" -DestinationPath "$($Env:TEMP)" -Force
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsFiles" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
        }
        else {
            fLogContent -fLogContent "Asset file ($assetFile) not present." -fLogContentComponent "windowsFiles"
        }
        #endregion
        [array]$windowsFileItems = $($config.windowsFiles.items)
        foreach ($windowsFileItem in $windowsFileItems) {
            fLogContent -fLogContent "Processing $($windowsFileItem.name)." -fLogContentComponent "windowsFiles"
            fLogContent -fLogContent "$($windowsFileItem.description)" -fLogContentComponent "windowsFiles"
            #region :: Build validation
            if ($([int]$windowsFileItem.minOSbuild) -eq 0) {
                fLogContent -fLogContent "minOSbuild: not specified" -fLogContentComponent "windowsFiles"
                [int]$windowsFileItem.minOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "minOSbuild: $($windowsFileItem.minOSbuild)" -fLogContentComponent "windowsFiles"
            }
            if ($([int]$windowsFileItem.maxOSbuild) -eq 0) {
                fLogContent -fLogContent "maxOSbuild: not specified" -fLogContentComponent "windowsFiles"
                [int]$windowsFileItem.maxOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "maxOSbuild: $($windowsFileItem.maxOSbuild)" -fLogContentComponent "windowsFiles"
            }
            #endregion
            if ($($([environment]::OSVersion.Version).Build) -ge $([int]$windowsFileItem.minOSbuild) -and $($([environment]::OSVersion.Version).Build) -le $([int]$windowsFileItem.maxOSbuild)) {
                #region :: Expanding Windows environment variables
                if ($($windowsFileItem.targetFile) -match "%\S+%") {
                    #[Environment]::ExpandEnvironmentVariables does not work in Constrained language mode - workaround to be explored.
                    if ($($ExecutionContext.SessionState.LanguageMode) -eq "FullLanguage") {
                        fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsFileItem.targetFile)." -fLogContentComponent "windowsFiles"
                        $windowsFileItem.targetFile = [Environment]::ExpandEnvironmentVariables($windowsFileItem.targetFile)
                        fLogContent -fLogContent "Windows Environment Variables resolved to $($windowsFileItem.targetFile)." -fLogContentComponent "windowsFiles"
                    }
                    else {
                        fLogContent -fLogContent "Windows Environment Variables is curently supported using Full Language mode only." -fLogContentComponent "windowsFiles"
                        fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsFileItem.targetFile) terminated." -fLogContentComponent "windowsFiles"
                        Continue
                    }
                }
                #endregion
                #region :: File copy process
                try {
                    if (Test-Path -Path "$($Env:TEMP)\$($windowsFileItem.sourceFile)" -PathType Leaf) {
                        fLogContent -fLogContent "$($Env:TEMP)\$($windowsFileItem.sourceFile) exist. Preparing copying file to $($windowsFileItem.targetFile)." -fLogContentComponent "windowsFiles"
                        if (!(Test-Path -path $(Split-Path -Path $($windowsFileItem.targetFile) -Parent))) {
                            fLogContent -fLogContent "Target folder not found, creating folder $(Split-Path -Path $($windowsFileItem.targetFile) -Parent)." -fLogContentComponent "windowsFiles"
                            New-Item $(Split-Path -Path $($windowsFileItem.targetFile) -Parent) -Type Directory -Force | Out-Null
                        }
                        fLogContent -fLogContent "Copying file to $($windowsFileItem.targetFile)." -fLogContentComponent "windowsFiles"
                        Copy-Item -Path "$($Env:TEMP)\$($windowsFileItem.sourceFile)" -Destination "$($windowsFileItem.targetFile)" -Force
                    }
                    else {
                        fLogContent -fLogContent "$($Env:TEMP)\$($windowsFileItem.sourceFile) not found. File copy canceled." -fLogContentComponent "windowsFiles"
                    }
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsFiles" -fLogContentType 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
                #endregion
            }
            else {
                fLogContent -fLogContent "Item $($windowsFileItem.description) entry not for this OS build." -fLogContentComponent "windowsFiles"
            }
        }
        fLogContent -fLogContent "Windows Files finished." -fLogContentComponent "windowsFiles"
    }
    else {
        fLogContent -fLogContent "Windows Files is disabled." -fLogContentComponent "windowsFiles"
    }
    #endregion
    #
    #region :: windowsGroups - PREVIEW
    ## windowsGroups is coming soon ##
    #endregion
    #
    #region :: windowsRegistry
    fLogContent -fLogContent "WINDOWS REGISTRY ITEMS" -fLogContentComponent "windowsRegistry"
    if ($($config.windowsRegistry.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Registry items is enabled" -fLogContentComponent "windowsRegistry"
        [array]$windowsRegistryItems = $($config.windowsRegistry.items)
        foreach ($windowsRegistryItem in $windowsRegistryItems) {
            fLogContent -fLogContent "Processing $($windowsRegistryItem.description)." -fLogContentComponent "windowsRegistry"
            if ($([int]$windowsRegistryItem.minOSbuild) -eq 0) {
                fLogContent -fLogContent "minOSbuild: not specified" -fLogContentComponent "windowsRegistry"
                [int]$windowsRegistryItem.minOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "minOSbuild: $($windowsRegistryItem.minOSbuild)" -fLogContentComponent "windowsRegistry"
            }
            if ($([int]$windowsRegistryItem.maxOSbuild) -eq 0) {
                fLogContent -fLogContent "maxOSbuild: not specified" -fLogContentComponent "windowsRegistry"
                [int]$windowsRegistryItem.maxOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "maxOSbuild: $($windowsRegistryItem.maxOSbuild)" -fLogContentComponent "windowsRegistry"
            }
            try {
                if ($($([environment]::OSVersion.Version).Build) -ge $([int]$windowsRegistryItem.minOSbuild) -and $($([environment]::OSVersion.Version).Build) -le $([int]$windowsRegistryItem.maxOSbuild)) {
                    switch ($($windowsRegistryItem.item).ToUpper()) {
                        "ADD" {
                            fLogContent -fLogContent "adding $($windowsRegistryItem.root):\$($windowsRegistryItem.path) [$($windowsRegistryItem.Type)] $($windowsRegistryItem.name) ""$($windowsRegistryItem.Value)""." -fLogContentComponent "windowsRegistry"
                            fRegistryItem -task "add" -froot "$($windowsRegistryItem.root)" -fpath "$($windowsRegistryItem.path)" -fname "$($windowsRegistryItem.name)" -fpropertyType "$($windowsRegistryItem.Type)" -fvalue "$($windowsRegistryItem.Value)"
                        }
                        "REMOVE" {
                            fLogContent -fLogContent "removing $($windowsRegistryItem.root):\$($windowsRegistryItem.path) ""$($windowsRegistryItem.name)"" setting from registry." -fLogContentComponent "windowsRegistry"
                            fRegistryItem -task "remove" -froot "$($windowsRegistryItem.root)" -fpath "$($windowsRegistryItem.path)" -fname "$($windowsRegistryItem.name)" -fpropertyType "$($windowsRegistryItem.Type)" -fvalue ""
                        }
                        Default {
                            fLogContent -fLogContent "unsupported value for [$($windowsRegistryItem.description)] | [$($windowsRegistryItem.item)]" -fLogContentComponent "windowsRegistry"
                        }
                    }
                }
                else {
                    fLogContent -fLogContent "item $($windowsRegistryItem.description) entry not for this OS build." -fLogContentComponent "windowsRegistry"
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsRegistry" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
        }
        fLogContent -fLogContent "Windows Registry items finished." -fLogContentComponent "windowsRegistry"
    }
    else {
        fLogContent -fLogContent "Windows Registry items is disabled." -fLogContentComponent "windowsRegistry"
    }
    #endregion
    #
    #region :: windowsRun
    fLogContent -fLogContent "WINDOWS EXECUTABLES" -fLogContentComponent "windowsRun"
    if ($($config.windowsRun.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Executables is enabled." -fLogContentComponent "windowsRun"
        [array]$windowsRun = $($config.windowsRun.items)
        foreach ($windowsExecutable in $windowsRun) {
            fLogContent -fLogContent "Processing $($windowsExecutable.name)" -fLogContentComponent "windowsRun"
            fLogContent -fLogContent "$($windowsExecutable.description)" -fLogContentComponent "windowsRun"
            #region :: Build validation
            if ($([int]$windowsExecutable.minOSbuild) -eq 0) {
                fLogContent -fLogContent "minOSbuild: not specified" -fLogContentComponent "windowsRun"
                [int]$windowsExecutable.minOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "minOSbuild: $($windowsExecutable.minOSbuild)" -fLogContentComponent "windowsRun"
            }
            if ($([int]$windowsExecutable.maxOSbuild) -eq 0) {
                fLogContent -fLogContent "maxOSbuild: not specified" -fLogContentComponent "windowsRun"
                [int]$windowsExecutable.maxOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "maxOSbuild: $($windowsExecutable.maxOSbuild)" -fLogContentComponent "windowsRun"
            }
            #endregion
            if ($($([environment]::OSVersion.Version).Build) -ge $([int]$windowsExecutable.minOSbuild) -and $($([environment]::OSVersion.Version).Build) -le $([int]$windowsExecutable.maxOSbuild)) {
                #region :: Expanding Windows environment variables
                if ($($windowsExecutable.filePath) -match "%\S+%") {
                    #[Environment]::ExpandEnvironmentVariables does not work in Constrained language mode - workaround to be explored.
                    if ($($ExecutionContext.SessionState.LanguageMode) -eq "FullLanguage") {
                        fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsExecutable.filePath)." -fLogContentComponent "windowsRun"
                        $windowsExecutable.filePath = [Environment]::ExpandEnvironmentVariables($windowsExecutable.filePath)
                        fLogContent -fLogContent "Windows Environment Variables resolved to $($windowsExecutable.filePath)." -fLogContentComponent "windowsRun"
                    }
                    else {
                        fLogContent -fLogContent "Windows Environment Variables is curently supported using Full Language mode only." -fLogContentComponent "windowsRun"
                        fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsExecutable.filePath) terminated." -fLogContentComponent "windowsRun"
                        Continue
                    }
                }
                #endregion
                #region :: download item
                if ($($windowsExecutable.downloadUri)) {
                    fLogContent -fLogContent "Download Uri $($windowsExecutable.downloadUri)" -fLogContentComponent "windowsRun"
                    fLogContent -fLogContent "Download target $($windowsExecutable.filePath)" -fLogContentComponent "windowsRun"
                    try {
                        $webRequestResponse = Invoke-WebRequest -Uri $($windowsExecutable.downloadUri) -OutFile $($windowsExecutable.filePath) -PassThru -UseBasicParsing
                        if ($webRequestResponse.StatusCode -eq 200) {
                            fLogContent -fLogContent "$((Get-Item $($windowsExecutable.filePath)).Name) downloaded successfully." -fLogContentComponent "windowsRun"
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsRun" -fLogContentType 3
                        if ($exitOnError) {
                            exit 1
                        }
                    }
                    finally {}
                }
                #endregion
                #region :: executing item
                if (Test-Path $($windowsExecutable.filePath)) {
                    fLogContent -fLogContent "File path $($windowsExecutable.filePath) exists." -fLogContentComponent "windowsRun"
                    fLogContent -fLogContent "File description $((Get-Item $($windowsExecutable.filePath)).VersionInfo.FileDescription)" -fLogContentComponent "windowsRun"
                    fLogContent -fLogContent "File version: $((Get-Item $($windowsExecutable.filePath)).VersionInfo.FileVersion)" -fLogContentComponent "windowsRun"
                    try {
                        if ($($windowsExecutable.ArgumentList)) {
                            fLogContent -fLogContent "Executing $($windowsExecutable.filePath) with arguments $($windowsExecutable.ArgumentList)." -fLogContentComponent "windowsRun"
                            Start-Process -FilePath $($windowsExecutable.filePath) -ArgumentList $($windowsExecutable.ArgumentList) -NoNewWindow -Wait

                        }
                        else {
                            fLogContent -fLogContent "Executing $($windowsExecutable.filePath) with no arguments." -fLogContentComponent "windowsRun"
                            Start-Process -FilePath $($windowsExecutable.filePath) -NoNewWindow -Wait
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsRun" -fLogContentType 3
                        if ($exitOnError) {
                            exit 1
                        }
                    }
                    finally {}
                }
                else {
                    fLogContent -fLogContent "File not found [$($windowsExecutable.filePath)]" -fLogContentComponent "windowsRun"
                }
                #endregion
            }
            else {
                fLogContent -fLogContent "Item $($windowsExecutable.description) entry not for this OS build." -fLogContentComponent "windowsRun"
            }
        }
        fLogContent -fLogContent "Windows Executables finished." -fLogContentComponent "windowsRun"
    }
    else {
        fLogContent -fLogContent "Windows Executables is disabled." -fLogContentComponent "windowsRun"
    }
    #endregion
    #
    #region :: windowsServices
    fLogContent -fLogContent "WINDOWS SERVICES" -fLogContentComponent "windowsServices"
    if ($($config.windowsServices.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Services is enabled." -fLogContentComponent "windowsServices"
        [array]$windowsServices = $($config.windowsServices.services)
        foreach ($windowsService in $windowsServices) {
            fLogContent -fLogContent "Processing $($windowsService.DisplayName) [$($windowsService.Name)]." -fLogContentComponent "windowsServices"
            try {
                [array]$windowsServiceStatus = Get-Service -Name "$($windowsService.Name)" -ErrorAction "SilentlyContinue"
                if ($windowsServiceStatus) {
                    fLogContent -fLogContent "$($windowsServiceStatus.DisplayName) found! | Status: $($windowsServiceStatus.Status) | StartType: $($windowsServiceStatus.StartType)." -fLogContentComponent "windowsServices"
                    if ($($windowsService.StartType) -eq $($windowsServiceStatus.StartType)) {
                        fLogContent -fLogContent "$($windowsService.Name) already configured." -fLogContentComponent "windowsServices"
                    }
                    else {
                        fLogContent -fLogContent "reconfigure $($windowsService.Name) [($($windowsServiceStatus.StartType) ->  $($windowsService.StartType))]." -fLogContentComponent "windowsServices"
                        Set-Service -Name "$($windowsService.Name)" -StartupType "$($windowsServiceStatus.StartType)"
                    }
                    if ($($windowsService.StopIfRunning) -eq $true -and $($windowsServiceStatus.Status) -eq "Running") {
                        fLogContent -fLogContent "Stopping $($windowsService.DisplayName) [$($windowsService.Name)]." -fLogContentComponent "windowsServices"
                        Stop-Service -Name "$($windowsService.Name)" -Force
                    }
                }
                else {
                    fLogContent -fLogContent "$($windowsService.DisplayName) not found!" -fLogContentComponent "windowsServices"
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsServices" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
        }
        fLogContent -fLogContent "Windows Services finished." -fLogContentComponent "windowsServices"
    }
    else {
        fLogContent -fLogContent "Windows Services is disabled." -fLogContentComponent "windowsServices"
    }
    #endregion
    #
    #region :: windowsTCR - PREVIEW
    fLogContent -fLogContent "WINDOWS TIME ZONE, CULTURE and REGIONAL SETTINGS MANAGER [PREVIEW]" -fLogContentComponent "windowsTCR - PREVIEW"
    if ($($config.windowsTCR.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Time zone, culture and regional settings manager is enabled." -fLogContentComponent "windowsTCR - PREVIEW"
        #
        [string]$windowsTCRfile = "$env:SystemDrive\Recovery\OEM\windowsTCR.json"
        [bool]$windowsTCRreconfigure = $false
        #
        fLogContent -fLogContent "Current Time zone: $((Get-TimeZone).Id)." -fLogContentComponent "windowsTCR - PREVIEW"
        [string]$timeZone = $((Get-TimeZone).Id)
        fLogContent -fLogContent "Current Culture: $((Get-Culture).Name)." -fLogContentComponent "windowsTCR - PREVIEW"
        [string]$culture = $((Get-Culture).Name)
        fLogContent -fLogContent "Windows UI Culture: $((Get-UICulture).Name)." -fLogContentComponent "windowsTCR - PREVIEW"
        fLogContent -fLogContent "Current Home Location GeoID: $((Get-WinHomeLocation).GeoId)." -fLogContentComponent "windowsTCR - PREVIEW"
        [int]$homeLocation = $((Get-WinHomeLocation).GeoId)
        #
        if ($CID) {
            fLogContent -fLogContent "Reading Windows Time zone, culture and regional settings from configuration file, using -CID parameter '$CID'." -fLogContentComponent "windowsTCR - PREVIEW"
            if ($config.windowsTCR.configuration.$CID) {
                fLogContent -fLogContent "Reading Windows Time zone, culture and regional settings from configuration file." -fLogContentComponent "windowsTCR - PREVIEW"
                try {
                    fLogContent -fLogContent "> Windows Time zone: $($config.windowsTCR.configuration.$CID.timezone)." -fLogContentComponent "windowsTCR - PREVIEW"
                    [string]$timeZone = $($config.windowsTCR.configuration.$CID.timezone)
                    fLogContent -fLogContent "> Windows culture: $($config.windowsTCR.configuration.$CID.culture)." -fLogContentComponent "windowsTCR - PREVIEW"
                    [string]$culture = $($config.windowsTCR.configuration.$CID.culture)
                    fLogContent -fLogContent "> Windows home location GeoId: $($config.windowsTCR.configuration.$CID.homelocation)." -fLogContentComponent "windowsTCR - PREVIEW"
                    [int]$homeLocation = $($config.windowsTCR.configuration.$CID.homelocation)
                    [bool]$windowsTCRreconfigure = $true
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsTCR - PREVIEW" -fLogContentType 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
            }
            else {
                fLogContent -fLogContent "Reading Windows Time zone, culture and regional settings from configuration, '$($CID.ToUpper())' value unknown." -fLogContentComponent "windowsTCR - PREVIEW" -fLogContentType 3
            }
        }
        else  {
            fLogContent -fLogContent "Reading Windows Time zone, culture and regional settings from configuration file not active, no '-CID' parameter." -fLogContentComponent "windowsTCR - PREVIEW" -fLogContentType 2
        }
        #
        if ($($config.windowsTCR.settings.windowsTCRfilerRead) -eq $true) {
            #
            if (Test-Path -Path $windowsTCRfile -PathType Leaf) {
                fLogContent -fLogContent "Reading Windows Time zone, culture and regional settings from local file ($windowsTCRfile)." -fLogContentComponent "windowsTCR - PREVIEW"
                try {
                    $windowsTCRsettings = Get-Content -Path $windowsTCRfile -Raw
                    $windowsTCRsettings = ConvertFrom-Json -InputObject $windowsTCRsettings
                    fLogContent -fLogContent "> Windows Time zone from file: $($windowsTCRsettings.timezone)." -fLogContentComponent "windowsTCR - PREVIEW"
                    [string]$timeZone = $($windowsTCRsettings.timezone)
                    fLogContent -fLogContent "> Windows culture from file: $($windowsTCRsettings.culture)." -fLogContentComponent "windowsTCR - PREVIEW"
                    [string]$culture = $($windowsTCRsettings.culture)
                    fLogContent -fLogContent "> Windows home location GeoId from file: $($windowsTCRsettings.homelocation)." -fLogContentComponent "windowsTCR - PREVIEW"
                    [int]$homeLocation = $($windowsTCRsettings.homelocation)
                    [bool]$windowsTCRreconfigure = $true
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsTCR - PREVIEW" -fLogContentType 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
            }
            else {
                fLogContent -fLogContent "Windows Time zone, culture and regional settings local file not present ($windowsTCRfile)." -fLogContentComponent "windowsTCR - PREVIEW"
                ## windowsTCR UI is coming soon ##
            }
        }
        else {
            fLogContent -fLogContent "Reading Windows Time zone, culture and regional settings from local file is disabled." -fLogContentComponent "windowsTCR - PREVIEW"
        }
        #
        if ($windowsTCRreconfigure) {
            fLogContent -fLogContent "Configuring Windows Time zone, culture and regional settings." -fLogContentComponent "windowsTCR - PREVIEW"
            try {
                fLogContent -fLogContent "> Setting Time zone: $((Get-TimeZone).Id) -> $($timeZone)." -fLogContentComponent "windowsTCR - PREVIEW"
                Set-TimeZone -Name $timezone
                fLogContent -fLogContent "> Setting Culture: $((Get-Culture).Name) -> $($culture)." -fLogContentComponent "windowsTCR - PREVIEW"
                Set-Culture -CultureInfo $culture
                fLogContent -fLogContent "> Setting Home Location GeoID: $((Get-WinHomeLocation).GeoId) -> $($homeLocation)." -fLogContentComponent "windowsTCR - PREVIEW"
                Set-WinHomeLocation -GeoId $homeLocation
                if ($($config.windowsTCR.settings.CopyUserInternationalSettingsToSystem) -eq $true) {
                    if ($($([environment]::OSVersion.Version).Build) -ge 22000) {
                        fLogContent -fLogContent "Copying user international settings to system." -fLogContentComponent "windowsTCR - PREVIEW"
                        Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true
                    } else {
                        fLogContent -fLogContent "Copying user international settings to system is not supported on this Windows build." -fLogContentType 2 -fLogContentComponent "windowsTCR - PREVIEW"
                    }
                }
                else {
                    fLogContent -fLogContent "Copying user international settings to system is disabled." -fLogContentComponent "windowsTCR - PREVIEW"
                }
                fLogContent -fLogContent "Configured Time zone: $((Get-TimeZone).Id)." -fLogContentComponent "windowsTCR - PREVIEW"
                #fLogContent -fLogContent "Configured Culture: $((Get-Culture).Name)." -fLogContentComponent "windowsTCR - PREVIEW"
                #Changes made by the use of Set-Culture cmdlet will take effect on subsequent PowerShell sessions - checking registry for LocaleName value.
                fLogContent -fLogContent "Configured Culture: $((Get-ItemProperty -Path "HKCU:\Control Panel\International" -Name "LocaleName").LocaleName)." -fLogContentComponent "windowsTCR - PREVIEW"
                fLogContent -fLogContent "Configured Home Location GeoID: $((Get-WinHomeLocation).GeoId)." -fLogContentComponent "windowsTCR - PREVIEW"
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsTCR - PREVIEW" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
            #
        }
        else {
            fLogContent -fLogContent "Windows Time zone, culture and regional settings re-configuration not required." -fLogContentComponent "windowsTCR - PREVIEW"
        }
        #
        if ($($config.windowsTCR.settings.windowsTCRfileSave) -eq $true) {
            fLogContent -fLogContent "Saving Windows Time zone, culture and regional settings to local file ($windowsTCRfile)." -fLogContentComponent "windowsTCR - PREVIEW"
            $windowsTCRcontent = @(
                [pscustomobject]@{timezone=$timezone;culture=$culture;homeLocation=$homeLocation;username=$($env:USERNAME)}
            )
            if (Test-Path -Path $windowsTCRfile -PathType "Leaf") {
                fLogContent -fLogContent "$windowsTCRfile exist, overwriting file." -fLogContentComponent "windowsTCR - PREVIEW"
            }
            else {
                fLogContent -fLogContent "$windowsTCRfile not found, creating file." -fLogContentComponent "windowsTCR - PREVIEW"
                New-Item -Path $windowsTCRfile -ItemType "File" -Force | Out-Null
            }
            fLogContent -fLogContent "Saving content to $windowsTCRfile." -fLogContentComponent "windowsTCR - PREVIEW"
            $windowsTCRcontent | ConvertTo-Json -Compress | Out-File -FilePath $windowsTCRfile -Encoding "utf8" -Force
        }
        else {
            fLogContent -fLogContent "Saving Windows Time zone, culture and regional settings to local file is disabled." -fLogContentComponent "windowsTCR - PREVIEW"
        }
    }
    else {
        fLogContent -fLogContent "Windows Time zone, culture and regional settings manager is disabled." -fLogContentComponent "windowsTCR - PREVIEW"
    }
    #endregion
    #
    #region :: metadata
    fLogContent -fLogContent "METADATA ITEMS" -fLogContentComponent "metadata"
    if ($($config.metadata.enabled) -eq $true) {
        fLogContent -fLogContent "Metadata items is enabled." -fLogContentComponent "metadata"
        switch ($($config.metadata.installBehavior).ToUpper()) {
            "SYSTEM" {
                $metadataRoot = "HKLM"
            }
            "USER" {
                $metadataRoot = "HKCU"
            }
            Default {
                fLogContent -fLogContent "ERROR: Processing metadata items failed." -fLogContentComponent "metadata" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
        }
        #region :: metadata entries
        try {
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "Comments" -fpropertyType "String" -fvalue "$($config.metadata.Comments)"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "DisplayName" -fpropertyType "String" -fvalue "$($config.metadata.title)"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "DisplayVersion" -fpropertyType "String" -fvalue "$($config.metadata.version)"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "InstallBehavior" -fpropertyType "String" -fvalue "$($config.metadata.installBehavior)"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "InstallDate" -fpropertyType "String" -fvalue "$(Get-Date -Format "yyyyMMdd")"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "Publisher" -fpropertyType "String" -fvalue "$($config.metadata.publisher)"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "SystemComponent" -fpropertyType "DWORD" -fvalue "1"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "Version" -fpropertyType "String" -fvalue "$($config.metadata.version)"
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsServices" -fLogContentType 3
            if ($exitOnError) {
                exit 1
            }
        }
        finally {}
        #endregion
        fLogContent -fLogContent "Metadata items finished." -fLogContentComponent "metadata"
    }
    else {
        fLogContent -fLogContent "Metadata items is disabled." -fLogContentComponent "metadata"
    }
    #endregion
}
end {
    #region :: resetting run Preference
    $ProgressPreference = $envProgressPreference
    $WarningPreference = $envWarningPreference
    #endregion
    fLogContent -fLogContent "Require reboot: $requireReboot" -fLogContentComponent "clean-up"
    #region :: cleaning-up
    fLogContent -fLogContent "Finishing up" -fLogContentComponent "clean-up"
    fLogContent -fLogContent "Cleaning up environment" -fLogContentComponent "clean-up"
    #endregion
}
#
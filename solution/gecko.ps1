<# PSScriptInfo
.VERSION 1.0.2.2
.GUID 10E1CBFB-EBAF-4329-87C1-225132847F61
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
    - WindowsBranding: Configure OEM information and Registration (PREVIEW).
    - WindowsFeatures
        - Enable and/or disable Windows features.
        - Enable and/or disable Windows optional features.
    - WindowsGroups: Add accounts to local groups (Coming soon).
    - WindowsFiles: Copy file(s) to device from payload package.
    - WindowsRegistry: Modifying Windows registry entries (add, change and remove).
    - WindowsRun: Run local executables and/or download and run executables.
    - WindowsServices: Configure/re-configure Windows Services.
    - WindowsTCR: Windows Time zone, culture, and regional settings manager (PREVIEW).
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
    Windows Time zone, culture, and regional settings value, allowing configuring culture, homelocation, and timezone from configuration file.
    Value must match windowsTCR.configuration.CID.[CID], e.g. "DEN", "565652" or similar. See sample files for more examples.
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
    .\gecko.ps1 -configFile ".\usercfg.json" -CID "DEN"
.EXAMPLE
    .\gecko.ps1 -configFile ".\usercfg.json" -logFile ".\usercfg.log" -Verbose
.EXAMPLE
    .\gecko.ps1 -configFile "https://<URL>/config.json"
#>
#requires -version 5.1
[CmdletBinding()]
param (
    #variables
    [Parameter(Mandatory = $false)]
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
    #region :: Environment
    #
    #endregion
    #region :: Parse configuation file
    if ($configFile.StartsWith("https://","CurrentCultureIgnoreCase")) {
        Write-Verbose -Message "Downloading configuration [$configFile]"
        try {
            $config = Invoke-WebRequest -Uri $configFile -UseBasicParsing -ErrorAction Stop 
            Write-Verbose -Message "Cloud configuration loaded [$($config | Select-Object -Expand StatusCode)]"
            $config = ConvertFrom-Json -InputObject $config.Content
            Write-Verbose -Message "Cloud configuration parsed"
        }
        catch {
            Write-Output -InputObject "Error reading cloud configuration file, script exiting [$($_.Exception.Response.StatusCode.Value__)]"
            throw $_.Exception.Message
            exit 1
        }
    }
    else {
        Write-Verbose -Message "Loading configuration [$configFile]"
        if (Test-Path -Path $configFile -PathType Leaf) {
            try {
                $config = Get-Content -Path $configFile -Raw
                Write-Verbose -Message "Configuration file loaded"
                $config = ConvertFrom-Json -InputObject $config
                Write-Verbose -Message "Configuration file parsed"
            }
            catch {
                Write-Output -InputObject "Error reading configuration file, script exiting"
                throw $_.Exception.Message
                exit 1
            }
        }
        else {
            Write-Output -InputObject "Cannot parse [$configFile] - file not found, script exiting"
            Write-Output -InputObject "> Go to https://github.com/dotjesper/windows-gecko/ to download sample configuration files"
            exit 1
        }
    }
    #endregion
    #region :: Environment configurations
    [bool]$requireReboot = $($config.runConditions.requireReboot)
    [string]$envProgressPreference = $ProgressPreference
    [string]$envWarningPreference = $WarningPreference
    if ($runSilent) {
        $ProgressPreference = "SilentlyContinue"
        $WarningPreference = "SilentlyContinue"
    }
    #endregion
    #region :: Logfile
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
        Write-Warning -Message "Unable to write to output file $fLogContentFile"
        Write-Verbose -Message $_.Exception.Message
        Write-Verbose -Message "Redireting output file to '$($Env:Temp)' folder"
        [string]$fLogContentFile = "$($Env:Temp)\$fLogContentpkg.log"
    }
    finally {}
    #endregion
    #
    #region :: Functions
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
            fLogContent -fLogContent "This is the log string" -fLogContentComponent "If applicable, add section, or component for log entry"
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
            Parameter will define registry root, valid values: HKCR, HKCU, HKDU, HKLM.
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
            #region :: Converting Default User (HKDU) registry value
            if ($froot -eq "HKDU") {
                fLogContent -fLogContent "re-register $($froot) to HKLM:\$defaultUserRegistryKey" -fLogContentComponent "fRegistryItem"
                $froot = "HKLM"
                $fpath = "$defaultUserRegistryKey\$fpath"
            }
            #endregion
            if ($($(Get-PSDrive -PSProvider "Registry" -Name "$froot" -ErrorAction "SilentlyContinue").Name)) {
                fLogContent -fLogContent "registry PSDrive $($froot) exists" -fLogContentComponent "fRegistryItem"
            }
            else {
                switch ("$froot") {
                    "HKCR" {
                        fLogContent -fLogContent "registry PSDrive $($froot) not found, creating PSDrive" -fLogContentComponent "fRegistryItem"
                        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Scope "Script" -Verbose:$false | Out-Null
                    }
                    "HKCU" {
                        fLogContent -fLogContent "registry PSDrive $($froot) not found, creating PSDrive" -fLogContentComponent "fRegistryItem"
                        New-PSDrive -Name "HKCU" -PSProvider "Registry" -Root "HKEY_CURRENT_USER" -Scope "Script" -Verbose:$false | Out-Null
                    }
                    "HKLM" {
                        fLogContent -fLogContent "registry PSDrive $($froot) not found, creating PSDrive" -fLogContentComponent "fRegistryItem"
                        New-PSDrive -Name "HKLM" -PSProvider "Registry" -Root "HKEY_LOCAL_MACHINE" -Scope "Script" -Verbose:$false | Out-Null
                    }
                    Default {
                        fLogContent -fLogContent "registry PSDrive $($froot) has an unknown or unsupported value, exiting" -fLogContentComponent "fRegistryItem"
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
                            fLogContent -fLogContent "registry path [$($froot):\$($fpath)] not found" -fLogContentComponent "fRegistryItem"
                            try {
                                New-Item -Path "$($froot):\$($fpath)" -Force | Out-Null
                                fLogContent -fLogContent "registry path [$($froot):\$($fpath)] created" -fLogContentComponent "fRegistryItem"
                            }
                            catch {
                                $errMsg = $_.Exception.Message
                                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "fRegistryItem" -fLogContentType 3
                            }
                            finally {}
                        }
                        else {
                            fLogContent -fLogContent "registry path [$($froot):\$($fpath)] exists" -fLogContentComponent "fRegistryItem"
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
                        if ($fname -eq "*") {
                            if (Test-Path -Path "$($froot):\$($fpath)") {
                                fLogContent -fLogContent "registry path [$($froot):\$($fpath)] exists" -fLogContentComponent "fRegistryItem"
                                fLogContent -fLogContent "deleting registry path [$($froot):\$($fpath)]" -fLogContentComponent "fRegistryItem"
                                Remove-Item -Path "$($froot):\$($fpath)" -Recurse -Force | Out-Null
                            }
                            else {
                                fLogContent -fLogContent "registry path [$($froot):\$($fpath)] not found" -fLogContentComponent "fRegistryItem"
                            }
                        }
                        else {
                            if (Get-ItemPropertyValue -Path "$($froot):\$($fpath)" -Name "$fname" -ErrorAction "SilentlyContinue") {
                                fLogContent -fLogContent "registry value [$($froot):\$($fpath)] : $($fname) found" -fLogContentComponent "fRegistryItem"
                                fLogContent -fLogContent "deleting registry value [$($froot):\$($fpath)] : $($fname)" -fLogContentComponent "fRegistryItem"
                                Remove-ItemProperty -Path "$($froot):\$($fpath)" -Name $($fname) -Force | Out-Null    
                            }
                            else {
                                fLogContent -fLogContent "registry value [$($froot):\$($fpath)] : $($fname) not found" -fLogContentComponent "fRegistryItem"
                            }
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
    #region :: Logfile environment entries
    $region = "environment"
    try {
        fLogContent -fLogContent "## $($config.metadata.title) by $($config.metadata.developer)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Config file: $($configFile)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Config file version: $($config.metadata.version) | $($config.metadata.date)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Config file description: $($config.metadata.description)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Log file: $($fLogContentFile)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Script name: $($MyInvocation.MyCommand.Name)" -fLogContentComponent "$region"
       #fLogContent -fLogContent "Command line: $($MyInvocation.Line)" -fLogContentComponent "$region"
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
        fLogContent -fLogContent "Command line: .\$($myInvocation.myCommand.name) $($argsString)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Run script in 64 bit PowerShell: $($config.runConditions.runScriptIn64bitPowerShell)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Running 64 bit PowerShell: $([System.Environment]::Is64BitProcess)" -fLogContentComponent "$region"
        if ($($ExecutionContext.SessionState.LanguageMode) -eq "FullLanguage") {
            fLogContent -fLogContent "Running elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" -fLogContentComponent "$region"
            fLogContent -fLogContent "Detected user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -fLogContentComponent "$region"
        }
        else {
            fLogContent -fLogContent "Detected user: $($Env:USERNAME)" -fLogContentComponent "$region"
        }
        fLogContent -fLogContent "Detected language mode: $($ExecutionContext.SessionState.LanguageMode)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Detected culture name: $((Get-Culture).Name)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Detected keyboard layout Id: $((Get-Culture).KeyboardLayoutId)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Detected computer name: $env:COMPUTERNAME" -fLogContentComponent "$region"
        fLogContent -fLogContent "Detected OS build: $($([environment]::OSVersion.Version).Build)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Detected Windows UI culture name: $((Get-UICulture).Name)" -fLogContentComponent "$region"
    }
    catch {
        $errMsg = $_.Exception.Message
        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
        if ($exitOnError) {
            exit 1
        }
    }
    finally {}
    #endregion
    #
    #region :: Check conditions
    $region = "conditions"
    if ($($config.runConditions.runScriptIn64bitPowerShell) -eq $true -and $([System.Environment]::Is64BitProcess) -eq $false) {
        fLogContent -fLogContent "Script must be run using 64-bit PowerShell" -fLogContentComponent "$region"
        try {
            fLogContent -fLogContent "Script relaunching using 64-bit PowerShell" -fLogContentComponent "$region"
           #fLogContent -fLogContent $("Command line: .\" + $($myInvocation.myCommand.name) + " " + $($argsString)) -fLogContentComponent "$region"
            Start-Process -FilePath "$env:windir\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList $("-ExecutionPolicy Bypass -File .\" + $($myInvocation.myCommand.name) + " " + $($argsString)) -Wait -NoNewWindow
            exit 0
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
            if ($exitOnError) {
                exit 1
            }
        }
    }
    #endregion
}
process {
    #region :: WindowsApps
    $region = "windowsApps"
    fLogContent -fLogContent "WINDOWS APPS" -fLogContentComponent "$region"
    if ($($config.windowsApps.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Apps is enabled" -fLogContentComponent "$region"
        [array]$windowsApps = $($config.windowsApps.apps)
        foreach ($windowsApp in $windowsApps) {
            fLogContent -fLogContent "Processing $($windowsApp.DisplayName)" -fLogContentComponent "$region"
            #region :: Appx Package
            try {
                [array]$AppxPackage = Get-AppxPackage -AllUsers -Name $($windowsApp.Name) -Verbose:$false
                if ($AppxPackage) {
                    fLogContent -fLogContent "$($windowsApp.DisplayName) is present" -fLogContentComponent "$region"
                    fLogContent -fLogContent "$($windowsApp.DisplayName) is bundle: $($AppxPackage.IsBundle)" -fLogContentComponent "$region"
                    fLogContent -fLogContent "$($windowsApp.DisplayName) is non-removable: $($AppxPackage.NonRemovable)" -fLogContentComponent "$region"
                    if ($($windowsApp.Remove) -eq $true) {
                        fLogContent -fLogContent "$($windowsApp.DisplayName) is being removed from all users" -fLogContentComponent "$region"
                        fLogContent -fLogContent "$($windowsApp.DisplayName) :: $($AppxPackage.Name)" -fLogContentComponent "$region"
                        fLogContent -fLogContent "$($windowsApp.DisplayName) :: $($AppxPackage.PackageFullName)" -fLogContentComponent "$region"
                        fLogContent -fLogContent "$($windowsApp.DisplayName) :: $($AppxPackage.PackageFamilyName)" -fLogContentComponent "$region"
                        fLogContent -fLogContent "$($windowsApp.DisplayName) :: $($AppxPackage.Version)" -fLogContentComponent "$region"
                        try {
                            Remove-AppxPackage -AllUsers -Package "$($AppxPackage.PackageFullName)" -Verbose:$false | Out-Null
                            #Get-AppxPackage -PackageTypeFilter Main, Bundle, Resource | Where-Object {$_.PackageFullName -eq "$($AppxPackage.PackageFullName)"} | Remove-AppxPackage -Allusers -Verbose:$false
                        }
                        catch {
                            $errMsg = $_.Exception.Message
                            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                            if ($exitOnError) {
                                exit 1
                            }
                        }
                        finally {}
                    }
                }
                else {
                    fLogContent -fLogContent "$($windowsApp.Name) not present" -fLogContentComponent "$region"
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
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
                    fLogContent -fLogContent "$($windowsApp.DisplayName) is present as provisioned app" -fLogContentComponent "windowsProvisionedApps"
                    fLogContent -fLogContent "$($windowsApp.DisplayName), $($AppxProvisionedPackage.DisplayName)" -fLogContentComponent "windowsProvisionedApps"
                    fLogContent -fLogContent "$($windowsApp.DisplayName), $($AppxProvisionedPackage.PackageName), $($AppxProvisionedPackage.Version)" -fLogContentComponent "windowsProvisionedApps"
                    fLogContent -fLogContent "$($windowsApp.DisplayName) remove: $($windowsApp.RemoveProvisionedPackage)" -fLogContentComponent "windowsProvisionedApps"
                    if ($($windowsApp.RemoveProvisionedPackage) -eq $true) {
                        fLogContent -fLogContent "$($AppxProvisionedPackage.DisplayName) is being removed" -fLogContentComponent "windowsProvisionedApps"
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
                    fLogContent -fLogContent "$($windowsApp.DisplayName) is not present" -fLogContentComponent "windowsProvisionedApps"
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
        fLogContent -fLogContent "Windows Apps finished" -fLogContentComponent "$region"
    }
    else {
        fLogContent -fLogContent "Windows Apps is disabled" -fLogContentComponent "$region"
    }
    #endregion
    #
    #region :: WindowsBranding - PREVIEW
    $region = "windows branding - PREVIEW"
    fLogContent -fLogContent "WINDOWS BRANDING" -fLogContentComponent "$region"
    if ($($config.windowsBranding.enabled) -eq $true) {
        fLogContent -fLogContent "Windows branding is enabled." -fLogContentComponent "$region"
        #region :: OEM Information
        foreach ($OEMInformationItem in $($config.windowsBranding.OEMInformationItems.PsObject.Properties)) {
            if ([string]::IsNullOrEmpty($OEMInformationItem.Value)) {
                fLogContent -fLogContent "> $($OEMInformationItem.Name) value is not defined" -fLogContentComponent "$region" -fLogContentType 2
            }
            else {
                fLogContent -fLogContent "> $($OEMInformationItem.Name) value is defined" -fLogContentComponent "$region"
                fLogContent -fLogContent "> Configuring $($OEMInformationItem.Name) value to '$($OEMInformationItem.Value)'" -fLogContentComponent "$region"
                fRegistryItem -task "add" -froot "HKLM" -fpath "SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -fname "$($OEMInformationItem.Name)" -fpropertyType "String" -fvalue "$($OEMInformationItem.Value)"
            }
        }
        #endregion
        #region :: Windows registation
        foreach ($registationItem in $($config.windowsBranding.registationItems.PsObject.Properties)) {
            if ([string]::IsNullOrEmpty($registationItem.Value)) {
                fLogContent -fLogContent "> $($registationItem.Name) value is not defined" -fLogContentComponent "$region" -fLogContentType 2
            }
            else {
                fLogContent -fLogContent "> $($registationItem.Name) value is defined" -fLogContentComponent "$region"
                fLogContent -fLogContent "> Configuring $($registationItem.Name) value to '$($registationItem.Value)'" -fLogContentComponent "$region"
                fRegistryItem -task "add" -froot "HKLM" -fpath "SOFTWARE\Microsoft\Windows NT\CurrentVersion" -fname "$($registationItem.Name)" -fpropertyType "String" -fvalue "$($registationItem.Value)"
            }
        }
        #endregion
        fLogContent -fLogContent "Windows branding finished" -fLogContentComponent "$region"
    }
    else {
        fLogContent -fLogContent "Windows branding is disabled" -fLogContentComponent "$region"
    }
    #endregion
    #
    #region :: WindowsFeatures
    $region = "windowsFeatures"
    fLogContent -fLogContent "WINDOWS FEATURES" -fLogContentComponent "$region"
    if ($($config.windowsFeatures.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Features is enabled" -fLogContentComponent "$region"
        #region :: WindowsFeatures
        [array]$windowsFeatures = $($config.windowsFeatures.features)
        foreach ($windowsFeature in $windowsFeatures) {
            fLogContent -fLogContent "Processing $($windowsFeature.DisplayName)" -fLogContentComponent "$region"
            try {
                [string]$featureState = $(Get-WindowsOptionalFeature -Online -FeatureName $($windowsFeature.FeatureName) -Verbose:$false).state
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
            if ($($windowsFeature.State) -eq $featureState) {
                fLogContent -fLogContent "$($windowsFeature.DisplayName) configured [$($windowsFeature.State)]" -fLogContentComponent "$region"
            }
            else {
                fLogContent -fLogContent "configuring $($windowsFeature.DisplayName) [$($windowsFeature.State)]" -fLogContentComponent "$region"
                try {
                    switch ($($windowsFeature.State).ToUpper()) {
                        "ENABLED" {
                            fLogContent -fLogContent "enabling $($windowsFeature.DisplayName)" -fLogContentComponent "$region"
                            $windowsFeatureResult = Enable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -All -NoRestart -Verbose:$false | Out-Null
                            if ($windowsFeatureResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished enabling $($windowsFeature.DisplayName). Restart needed: $($windowsFeatureResult.RestartNeeded)" -fLogContentComponent "$region"
                        }
                        "DISABLED" {
                            fLogContent -fLogContent "disabling $($windowsFeature.DisplayName)" -fLogContentComponent "$region"
                            $windowsFeatureResult = Disable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -NoRestart -Verbose:$false
                            if ($windowsFeatureResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished disabling $($windowsFeature.DisplayName). Restart needed: $($windowsFeatureResult.RestartNeeded)" -fLogContentComponent "$region"
                        }
                        Default {
                            fLogContent -fLogContent "unsupported state $($windowsFeature.DisplayName) [$($windowsFeature.State)]" -fLogContentComponent "$region"
                        }
                    }
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
            }
        }
        #endregion
        #region :: WindowsOptionalFeatures
        fLogContent -fLogContent "WINDOWS OPTIONAL FEATURES" -fLogContentComponent "windowsOptionalFeatures"
        [array]$windowsOptionalFeatures = $($config.windowsFeatures.optionalFeatures)
        foreach ($windowsOptionalFeature in $windowsOptionalFeatures) {
            fLogContent -fLogContent "Processing $($windowsOptionalFeature.DisplayName)" -fLogContentComponent "windowsOptionalFeatures"
            [string]$featureState = $(Get-WindowsCapability -Online -Name $($windowsOptionalFeature.Name) -Verbose:$false).state
            if ($($windowsOptionalFeature.State) -eq $featureState) {
                fLogContent -fLogContent "$($windowsOptionalFeature.DisplayName) configured [$($windowsOptionalFeature.State)]" -fLogContentComponent "windowsOptionalFeatures"
            }
            else {
                fLogContent -fLogContent "configuring $($windowsOptionalFeature.DisplayName) [$($windowsOptionalFeature.State)]" -fLogContentComponent "windowsOptionalFeatures"
                switch ($($windowsOptionalFeature.State).ToUpper()) {
                    "INSTALLED" {
                        fLogContent -fLogContent "installing $($windowsOptionalFeature.DisplayName)" -fLogContentComponent "windowsOptionalFeatures"
                        try {
                            $windowsCapabilityResult = Add-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false
                            if ($windowsCapabilityResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished installing $($windowsOptionalFeature.DisplayName), restart needed: $($windowsCapabilityResult.RestartNeeded)" -fLogContentComponent "$region"
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
                        fLogContent -fLogContent "removing $($windowsOptionalFeature.DisplayName)" -fLogContentComponent "windowsOptionalFeatures"
                        try {
                            $windowsCapabilityResult = Remove-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false
                            if ($windowsCapabilityResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished removing $($windowsOptionalFeature.DisplayName), restart needed: $($windowsCapabilityResult.RestartNeeded)" -fLogContentComponent "$region"
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
                        fLogContent -fLogContent "unsupported state $($windowsOptionalFeature.DisplayName) [$($windowsOptionalFeature.State)]" -fLogContentComponent "windowsOptionalFeatures"
                    }
                }
            }
        }
        #endregion
        fLogContent -fLogContent "Windows Features finished" -fLogContentComponent "$region"
    }
    else {
        fLogContent -fLogContent "Windows Features is disabled" -fLogContentComponent "$region"
    }
    #endregion
    #
    #region :: WindowsFiles
    $region = "windowsFiles"
    fLogContent -fLogContent "WINDOWS FILES" -fLogContentComponent "$region"
    if ($($config.windowsFiles.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Files is enabled" -fLogContentComponent "$region"
        [string]$assetFile = $($config.windowsFiles.assetFile)
        if ($assetFile.StartsWith("https://","CurrentCultureIgnoreCase")) {
            #region :: Download cloud asset file
            fLogContent -fLogContent "Downloading asset file [$($assetFile)]" -fLogContentComponent "$region"
            $assetOutFile = "$($Env:TEMP)\$(Split-Path -Leaf $assetFile)"
            try {
                $webRequestResponse = Invoke-WebRequest -Uri $assetFile -OutFile $assetOutFile -PassThru -UseBasicParsing
                if ($webRequestResponse.StatusCode -eq 200) {
                    fLogContent -fLogContent "$(Split-Path -Leaf $assetFile) downloaded successfully [$($assetOutFile)]" -fLogContentComponent "$region"
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
            #endregion
            #region :: Expand cloud asset file
            if (Test-Path -Path $assetOutFile -PathType Leaf) {
                fLogContent -fLogContent "Windows Files found $($assetOutFile)" -fLogContentComponent "$region"
                fLogContent -fLogContent "Windows Files is expanding $($assetOutFile)" -fLogContentComponent "$region"
                try {
                    Expand-Archive -Path "$assetOutFile" -DestinationPath "$($Env:TEMP)" -Force
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
            }
            else {
                fLogContent -fLogContent "Asset file ($assetOutFile) not present" -fLogContentComponent "$region"
            }
            #endregion
        }
        else {
            #region :: Expand local asset file
            if (Test-Path -Path $assetFile -PathType Leaf) {
                fLogContent -fLogContent "Windows Files found $assetFile" -fLogContentComponent "$region"
                fLogContent -fLogContent "Windows Files is expanding $((Get-Item $assetFile).FullName)" -fLogContentComponent "$region"
                try {
                    Expand-Archive -Path "$assetFile" -DestinationPath "$($Env:TEMP)" -Force
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
            }
            else {
                fLogContent -fLogContent "Asset file ($assetFile) not present" -fLogContentComponent "$region"
            }
            #endregion
        }
        [array]$windowsFileItems = $($config.windowsFiles.items)
        foreach ($windowsFileItem in $windowsFileItems) {
            fLogContent -fLogContent "Processing $($windowsFileItem.name)" -fLogContentComponent "$region"
            fLogContent -fLogContent "$($windowsFileItem.description)" -fLogContentComponent "$region"
            #region :: Build validation
            if ($([int]$windowsFileItem.minOSbuild) -eq 0) {
                fLogContent -fLogContent "minOSbuild: not specified" -fLogContentComponent "$region"
                [int]$windowsFileItem.minOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "minOSbuild: $($windowsFileItem.minOSbuild)" -fLogContentComponent "$region"
            }
            if ($([int]$windowsFileItem.maxOSbuild) -eq 0) {
                fLogContent -fLogContent "maxOSbuild: not specified" -fLogContentComponent "$region"
                [int]$windowsFileItem.maxOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "maxOSbuild: $($windowsFileItem.maxOSbuild)" -fLogContentComponent "$region"
            }
            #endregion
            if ($($([environment]::OSVersion.Version).Build) -ge $([int]$windowsFileItem.minOSbuild) -and $($([environment]::OSVersion.Version).Build) -le $([int]$windowsFileItem.maxOSbuild)) {
                #region :: Expanding Windows environment variables
                if ($($windowsFileItem.targetFile) -match "%\S+%") {
                    #[Environment]::ExpandEnvironmentVariables does not work in Constrained language mode - workaround to be explored.
                    if ($($ExecutionContext.SessionState.LanguageMode) -eq "FullLanguage") {
                        fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsFileItem.targetFile)" -fLogContentComponent "$region"
                        $windowsFileItem.targetFile = [Environment]::ExpandEnvironmentVariables($windowsFileItem.targetFile)
                        fLogContent -fLogContent "Windows Environment Variables resolved to $($windowsFileItem.targetFile)" -fLogContentComponent "$region"
                    }
                    else {
                        fLogContent -fLogContent "Windows Environment Variables is curently supported using Full Language mode only" -fLogContentComponent "$region"
                        fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsFileItem.targetFile) terminated" -fLogContentComponent "$region"
                        Continue
                    }
                }
                #endregion
                #region :: File copy process
                try {
                    if (Test-Path -Path "$($Env:TEMP)\$($windowsFileItem.sourceFile)" -PathType Leaf) {
                        fLogContent -fLogContent "$($Env:TEMP)\$($windowsFileItem.sourceFile) exist. Preparing copying file to $($windowsFileItem.targetFile)" -fLogContentComponent "$region"
                        if (!(Test-Path -path $(Split-Path -Path $($windowsFileItem.targetFile) -Parent))) {
                            fLogContent -fLogContent "Target folder not found, creating folder $(Split-Path -Path $($windowsFileItem.targetFile) -Parent)" -fLogContentComponent "$region"
                            New-Item $(Split-Path -Path $($windowsFileItem.targetFile) -Parent) -Type Directory -Force | Out-Null
                        }
                        fLogContent -fLogContent "Copying file to $($windowsFileItem.targetFile)" -fLogContentComponent "$region"
                        Copy-Item -Path "$($Env:TEMP)\$($windowsFileItem.sourceFile)" -Destination "$($windowsFileItem.targetFile)" -Force
                    }
                    else {
                        fLogContent -fLogContent "$($Env:TEMP)\$($windowsFileItem.sourceFile) not found. File copy canceled" -fLogContentComponent "$region"
                    }
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
                #endregion
            }
            else {
                fLogContent -fLogContent "Item $($windowsFileItem.description) entry not for this OS build" -fLogContentComponent "$region"
            }
        }
        fLogContent -fLogContent "Windows Files finished" -fLogContentComponent "$region"
    }
    else {
        fLogContent -fLogContent "Windows Files is disabled" -fLogContentComponent "$region"
    }
    #endregion
    #
    #region :: WindowsGroups - PREVIEW
    ## windowsGroups is coming soon ##
    #endregion
    #
    #region :: WindowsRegistry
    $region = "windowsRegistry"
    fLogContent -fLogContent "WINDOWS REGISTRY ITEMS" -fLogContentComponent "$region"
    if ($($config.windowsRegistry.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Registry items is enabled" -fLogContentComponent "$region"
        [array]$windowsRegistryItems = $($config.windowsRegistry.items)
        #
        #region :: Loading Default User registry hive (NTuser.dat)
        if ($windowsRegistryItems.root -contains "HKDU") {
            fLogContent -fLogContent "Default User Registry item(s) found" -fLogContentComponent "$region"
            $defaultUserRegistryFile = "$env:SystemDrive\Users\Default\NTuser.dat"
            $defaultUserRegistryRoot = "HKLM"
            $defaultUserRegistryKey = ".DEFAULTUSER"
            fLogContent -fLogContent "Loading Default User registry hive ($DefaultUserRegistryFile)" -fLogContentComponent "$region"
            try {
                $processResult = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "LOAD $defaultUserRegistryRoot\$defaultUserRegistryKey $defaultUserRegistryFile" -WindowStyle Hidden -PassThru -Wait

                if ($processResult.ExitCode -eq 0) {
                    fLogContent -fLogContent "Successfully loaded Default User Registry hive as '$defaultUserRegistryRoot\$defaultUserRegistryKey'" -fLogContentComponent "$region"
                }
                else {
                    fLogContent -fLogContent "Failed loading Default User Registry hive as '$defaultUserRegistryRoot\$defaultUserRegistryKey'" -fLogContentComponent "$region"  -fLogContentType 3
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
        }
        else {
            fLogContent -fLogContent "Loading Default User Registry hive not required" -fLogContentComponent "$region"
        }
        #endregion
        #
        #region :: Processing Windows Registry Items
        foreach ($windowsRegistryItem in $windowsRegistryItems) {
            fLogContent -fLogContent "Processing $($windowsRegistryItem.description)" -fLogContentComponent "$region"
            if ($([int]$windowsRegistryItem.minOSbuild) -eq 0) {
                fLogContent -fLogContent "minOSbuild: not specified" -fLogContentComponent "$region"
                [int]$windowsRegistryItem.minOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "minOSbuild: $($windowsRegistryItem.minOSbuild)" -fLogContentComponent "$region"
            }
            if ($([int]$windowsRegistryItem.maxOSbuild) -eq 0) {
                fLogContent -fLogContent "maxOSbuild: not specified" -fLogContentComponent "$region"
                [int]$windowsRegistryItem.maxOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "maxOSbuild: $($windowsRegistryItem.maxOSbuild)" -fLogContentComponent "$region"
            }
            try {
                if ($($([environment]::OSVersion.Version).Build) -ge $([int]$windowsRegistryItem.minOSbuild) -and $($([environment]::OSVersion.Version).Build) -le $([int]$windowsRegistryItem.maxOSbuild)) {
                    switch ($($windowsRegistryItem.item).ToUpper()) {
                        "ADD" {
                            fLogContent -fLogContent "adding $($windowsRegistryItem.root):\$($windowsRegistryItem.path) [$($windowsRegistryItem.Type)] $($windowsRegistryItem.name) ""$($windowsRegistryItem.Value)""" -fLogContentComponent "$region"
                            fRegistryItem -task "add" -froot "$($windowsRegistryItem.root)" -fpath "$($windowsRegistryItem.path)" -fname "$($windowsRegistryItem.name)" -fpropertyType "$($windowsRegistryItem.Type)" -fvalue "$($windowsRegistryItem.Value)"
                        }
                        "REMOVE" {
                            fLogContent -fLogContent "removing $($windowsRegistryItem.root):\$($windowsRegistryItem.path) ""$($windowsRegistryItem.name)"" setting from registry" -fLogContentComponent "$region"
                            fRegistryItem -task "remove" -froot "$($windowsRegistryItem.root)" -fpath "$($windowsRegistryItem.path)" -fname "$($windowsRegistryItem.name)" -fpropertyType "$($windowsRegistryItem.Type)" -fvalue ""
                        }
                        Default {
                            fLogContent -fLogContent "unsupported value for [$($windowsRegistryItem.description)] | [$($windowsRegistryItem.item)]" -fLogContentComponent "$region"
                        }
                    }
                }
                else {
                    fLogContent -fLogContent "item $($windowsRegistryItem.description) entry not for this OS build" -fLogContentComponent "$region"
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
        }
        #endregion
        #
        #region :: Unloading Default User registry hive (NTuser.dat)
        if ($processResult.ExitCode -eq 0) {
            fLogContent -fLogContent "Unloading Default User Registry hive" -fLogContentComponent "$region"
            do {
                fLogContent -fLogContent "Sleeping 15 secunds before attemting unloading Default User Registry hive" -fLogContentComponent "$region"
                Start-Sleep -Seconds 15
                [gc]::Collect()
                $processResult = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "UNLOAD $defaultUserRegistryRoot\$defaultUserRegistryKey" -WindowStyle Hidden -PassThru -Wait
                $counter++
                fLogContent -fLogContent "Unloading Default User Registry hive attempted [ $($processResult.ExitCode) | $($counter) ]" -fLogContentComponent "$region"
            }
            While (($processResult.ExitCode -gt 0) -and ($counter -le 3))
            if ($processResult.ExitCode -eq 0) {
                fLogContent -fLogContent "Successfully unloaded Default User Registry hive" -fLogContentComponent "$region"
            }
            else {
                fLogContent -fLogContent "Failed unloading Default User Registry hive" -fLogContentComponent "$region"  -fLogContentType 3
            }
        }
        #endregion
        fLogContent -fLogContent "Windows Registry items finished" -fLogContentComponent "$region"
    }
    else {
        fLogContent -fLogContent "Windows Registry items is disabled" -fLogContentComponent "$region"
    }
    #endregion
    #
    #region :: WindowsRun
    $region = "windowsRun"
    fLogContent -fLogContent "WINDOWS EXECUTABLES" -fLogContentComponent "$region"
    if ($($config.windowsRun.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Executables is enabled" -fLogContentComponent "$region"
        [array]$windowsRun = $($config.windowsRun.items)
        foreach ($windowsExecutable in $windowsRun) {
            fLogContent -fLogContent "Processing $($windowsExecutable.name)" -fLogContentComponent "$region"
            fLogContent -fLogContent "$($windowsExecutable.description)" -fLogContentComponent "$region"
            #region :: Build validation
            if ($([int]$windowsExecutable.minOSbuild) -eq 0) {
                fLogContent -fLogContent "minOSbuild: not specified" -fLogContentComponent "$region"
                [int]$windowsExecutable.minOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "minOSbuild: $($windowsExecutable.minOSbuild)" -fLogContentComponent "$region"
            }
            if ($([int]$windowsExecutable.maxOSbuild) -eq 0) {
                fLogContent -fLogContent "maxOSbuild: not specified" -fLogContentComponent "$region"
                [int]$windowsExecutable.maxOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "maxOSbuild: $($windowsExecutable.maxOSbuild)" -fLogContentComponent "$region"
            }
            #endregion
            if ($($([environment]::OSVersion.Version).Build) -ge $([int]$windowsExecutable.minOSbuild) -and $($([environment]::OSVersion.Version).Build) -le $([int]$windowsExecutable.maxOSbuild)) {
                #region :: Expanding Windows environment variables
                if ($($windowsExecutable.filePath) -match "%\S+%") {
                    #[Environment]::ExpandEnvironmentVariables does not work in Constrained language mode - workaround to be explored.
                    if ($($ExecutionContext.SessionState.LanguageMode) -eq "FullLanguage") {
                        fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsExecutable.filePath)" -fLogContentComponent "$region"
                        $windowsExecutable.filePath = [Environment]::ExpandEnvironmentVariables($windowsExecutable.filePath)
                        fLogContent -fLogContent "Windows Environment Variables resolved to $($windowsExecutable.filePath)" -fLogContentComponent "$region"
                    }
                    else {
                        fLogContent -fLogContent "Windows Environment Variables is curently supported using Full Language mode only" -fLogContentComponent "$region"
                        fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsExecutable.filePath) terminated" -fLogContentComponent "$region"
                        Continue
                    }
                }
                #endregion
                #region :: Download item
                if ($($windowsExecutable.downloadUri)) {
                    fLogContent -fLogContent "Download Uri $($windowsExecutable.downloadUri)" -fLogContentComponent "$region"
                    fLogContent -fLogContent "Download target $($windowsExecutable.filePath)" -fLogContentComponent "$region"
                    try {
                        $webRequestResponse = Invoke-WebRequest -Uri $($windowsExecutable.downloadUri) -OutFile $($windowsExecutable.filePath) -PassThru -UseBasicParsing
                        if ($webRequestResponse.StatusCode -eq 200) {
                            fLogContent -fLogContent "$((Get-Item $($windowsExecutable.filePath)).Name) downloaded successfully" -fLogContentComponent "$region"
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                        if ($exitOnError) {
                            exit 1
                        }
                    }
                    finally {}
                }
                #endregion
                #region :: Executing item
                if (Test-Path $($windowsExecutable.filePath)) {
                    fLogContent -fLogContent "File path $($windowsExecutable.filePath) exists" -fLogContentComponent "$region"
                    fLogContent -fLogContent "File description $((Get-Item $($windowsExecutable.filePath)).VersionInfo.FileDescription)" -fLogContentComponent "$region"
                    fLogContent -fLogContent "File version: $((Get-Item $($windowsExecutable.filePath)).VersionInfo.FileVersion)" -fLogContentComponent "$region"
                    try {
                        if ($($windowsExecutable.ArgumentList)) {
                            fLogContent -fLogContent "Executing $($windowsExecutable.filePath) with arguments $($windowsExecutable.ArgumentList)" -fLogContentComponent "$region"
                            Start-Process -FilePath $($windowsExecutable.filePath) -ArgumentList $($windowsExecutable.ArgumentList) -NoNewWindow -Wait

                        }
                        else {
                            fLogContent -fLogContent "Executing $($windowsExecutable.filePath) with no arguments" -fLogContentComponent "$region"
                            Start-Process -FilePath $($windowsExecutable.filePath) -NoNewWindow -Wait
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                        if ($exitOnError) {
                            exit 1
                        }
                    }
                    finally {}
                }
                else {
                    fLogContent -fLogContent "File not found [$($windowsExecutable.filePath)]" -fLogContentComponent "$region"
                }
                #endregion
            }
            else {
                fLogContent -fLogContent "Item $($windowsExecutable.description) entry not for this OS build" -fLogContentComponent "$region"
            }
        }
        fLogContent -fLogContent "Windows Executables finished" -fLogContentComponent "$region"
    }
    else {
        fLogContent -fLogContent "Windows Executables is disabled" -fLogContentComponent "$region"
    }
    #endregion
    #
    #region :: WindowsServices
    $region = "windowsServices"
    fLogContent -fLogContent "WINDOWS SERVICES" -fLogContentComponent "$region"
    if ($($config.windowsServices.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Services is enabled" -fLogContentComponent "$region"
        [array]$windowsServices = $($config.windowsServices.services)
        foreach ($windowsService in $windowsServices) {
            fLogContent -fLogContent "Processing $($windowsService.DisplayName) [$($windowsService.Name)]" -fLogContentComponent "$region"
            try {
                [array]$windowsServiceStatus = Get-Service -Name "$($windowsService.Name)" -ErrorAction "SilentlyContinue"
                if ($windowsServiceStatus) {
                    fLogContent -fLogContent "$($windowsServiceStatus.DisplayName) found! | Status: $($windowsServiceStatus.Status) | StartType: $($windowsServiceStatus.StartType)" -fLogContentComponent "$region"
                    if ($($windowsService.StartType) -eq $($windowsServiceStatus.StartType)) {
                        fLogContent -fLogContent "$($windowsService.Name) already configured" -fLogContentComponent "$region"
                    }
                    else {
                        fLogContent -fLogContent "reconfigure $($windowsService.Name) [($($windowsServiceStatus.StartType) ->  $($windowsService.StartType))]" -fLogContentComponent "$region"
                        Set-Service -Name "$($windowsService.Name)" -StartupType "$($windowsServiceStatus.StartType)"
                    }
                    if ($($windowsService.StopIfRunning) -eq $true -and $($windowsServiceStatus.Status) -eq "Running") {
                        fLogContent -fLogContent "Stopping $($windowsService.DisplayName) [$($windowsService.Name)]" -fLogContentComponent "$region"
                        Stop-Service -Name "$($windowsService.Name)" -Force
                    }
                }
                else {
                    fLogContent -fLogContent "$($windowsService.DisplayName) not found!" -fLogContentComponent "$region"
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
        }
        fLogContent -fLogContent "Windows Services finished" -fLogContentComponent "$region"
    }
    else {
        fLogContent -fLogContent "Windows Services is disabled" -fLogContentComponent "$region"
    }
    #endregion
    #
    #region :: WindowsTCR - PREVIEW
    $region = "windowsTCR - PREVIEW"
    fLogContent -fLogContent "WINDOWS TIME ZONE, CULTURE, AND REGIONAL SETTINGS MANAGER [PREVIEW]" -fLogContentComponent "$region"
    if ($($config.windowsTCR.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Time zone, culture, and regional settings manager is enabled" -fLogContentComponent "$region"
        #
        fLogContent -fLogContent "Current Time zone: $((Get-TimeZone).Id)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Current Culture: $((Get-Culture).Name)" -fLogContentComponent "$region"
        fLogContent -fLogContent "Current Home Location GeoID: $((Get-WinHomeLocation).GeoId)" -fLogContentComponent "$region"
        #
        fLogContent -fLogContent "Reading Windows Time zone, culture, and regional settings from configuration file" -fLogContentComponent "$region"
        [array]$windowsTCRconfigurations = $($config.windowsTCR.configurations)
        #
        if ($windowsTCRconfigurations.Count -ge 1) {
            fLogContent -fLogContent "Found $($windowsTCRconfigurations.Count) Windows Time zone, culture, and regional settings configurations" -fLogContentComponent "$region"
            if ($CID) {
                fLogContent -fLogContent "Windows Time zone, culture, and regional settings CID value defined ($CID)" -fLogContentComponent "$region"
                $CIDvalue = $CID
            }
            else  {
                fLogContent -fLogContent "Windows Time zone, culture, and regional settings CID value not defined, looking up default value" -fLogContentComponent "$region"
                if ([string]::IsNullOrEmpty($config.windowsTCR.settings.windowsTCRdefault)) {
                    fLogContent -fLogContent "Windows Time zone, culture, and regional settings default value not defined" -fLogContentComponent "$region"
                }
                else {
                    fLogContent -fLogContent "Windows Time zone, culture, and regional settings default value found, setting CID value to '$($config.windowsTCR.settings.windowsTCRdefault)'" -fLogContentComponent "$region"
                    $CIDvalue = ($config.windowsTCR.settings.windowsTCRdefault)
                }
            }
            #region :: Computer name comparison
            if ($config.windowsTCR.settings.useComputerName) {
                fLogContent -fLogContent "Computer name comparison enabled" -fLogContentComponent "$region"
                fLogContent -fLogContent "> Computer name '$env:COMPUTERNAME'" -fLogContentComponent "$region"
                foreach ($CIDitem in $config.windowsTCR.configurations.CID) {
                    fLogContent -fLogContent "> Checking if computer name $($config.windowsTCR.settings.useComputerNameOperator) '$CIDitem'" -fLogContentComponent "$region"
                    if ($env:COMPUTERNAME.$($config.windowsTCR.settings.useComputerNameOperator)("$CIDitem")) {
                        fLogContent -fLogContent "> $env:COMPUTERNAME $($config.windowsTCR.settings.useComputerNameOperator) '$CIDitem'" -fLogContentComponent "$region"
                        fLogContent -fLogContent "> Configuring CID value to '$CIDitem'" -fLogContentComponent "$region"
                        $CIDfound = $true
                        break
                    }
                }
                if ($CIDfound) {
                    fLogContent -fLogContent "> Overwriting CID value with value from computer name comparison" -fLogContentComponent "$region"
                    $CIDvalue = $CIDitem
                }
                else {
                    fLogContent -fLogContent "Computer name comparison did not find a match" -fLogContentComponent "$region" -fLogContentType 2
                }
            }
            else {
                fLogContent -fLogContent "Computer name comparison disabled" -fLogContentComponent "$region"
            }
            #endregion
            #region :: Configure WindowsTCR configurations
            if ($windowsTCRconfigurations.CID -contains $CIDvalue) {
                fLogContent -fLogContent "Valid Windows Time zone, culture, and regional settings CID value, querying '$CIDvalue'" -fLogContentComponent "$region"
                $windowsTCRSettings = $($config.windowsTCR.configurations) | Where-Object {$_.CID -eq $CIDvalue}
                fLogContent -fLogContent "Configuring Windows Time zone, culture, and regional settings" -fLogContentComponent "$region"
                if ([string]::IsNullOrEmpty($windowsTCRSettings.description)) {
                    fLogContent -fLogContent "> -- no description --" -fLogContentComponent "$region"
                }
                else {
                    fLogContent -fLogContent "> $($windowsTCRSettings.description)" -fLogContentComponent "$region"
                }
                try {
                    fLogContent -fLogContent "> Setting Time zone: $((Get-TimeZone).Id) -> $($windowsTCRSettings.timezone)" -fLogContentComponent "$region"
                    Set-TimeZone -Name $($windowsTCRSettings.timezone)
                    fLogContent -fLogContent "> Setting Culture: $((Get-Culture).Name) -> $($windowsTCRSettings.culture)" -fLogContentComponent "$region"
                    Set-Culture -CultureInfo $($windowsTCRSettings.culture)
                    fLogContent -fLogContent "> Setting Home Location GeoID: $((Get-WinHomeLocation).GeoId) -> $($windowsTCRSettings.homelocation)" -fLogContentComponent "$region"
                    Set-WinHomeLocation -GeoId $($windowsTCRSettings.homelocation)
                    try {
                        if ($($config.windowsTCR.settings.CopyUserInternationalSettingsToSystem)) {
                            if ($($([environment]::OSVersion.Version).Build) -ge 22000) {
                                fLogContent -fLogContent "Copying user international settings to Welcome Screen and New Users" -fLogContentComponent "$region"
                                Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true
                            } else {
                                fLogContent -fLogContent "Copying user international settings to system is not supported on this Windows build" -fLogContentComponent "$region" -fLogContentType 2
                            }
                        }
                        else {
                            fLogContent -fLogContent "Copying user international settings to system is disabled" -fLogContentComponent "$region"
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                        if ($exitOnError) {
                            exit 1
                        }
                    }
                    finally {}
                    fLogContent -fLogContent "Configured Time zone: $((Get-TimeZone).Id)" -fLogContentComponent "$region"
                    #fLogContent -fLogContent "Configured Culture: $((Get-Culture).Name)" -fLogContentComponent "$region"
                    #Changes made by the use of Set-Culture cmdlet will take effect on subsequent PowerShell sessions - checking registry for LocaleName value.
                    fLogContent -fLogContent "Configured Culture: $((Get-ItemProperty -Path "HKCU:\Control Panel\International" -Name "LocaleName").LocaleName)" -fLogContentComponent "$region"
                    fLogContent -fLogContent "Configured Home Location GeoID: $((Get-WinHomeLocation).GeoId)" -fLogContentComponent "$region"
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
            }
            else {
                fLogContent -fLogContent "Windows Time zone, culture, and regional settings CID value unknown or empty" -fLogContentComponent "$region" -fLogContentType 2
                fLogContent -fLogContent "Windows Time zone, culture, and regional settings not re-configured" -fLogContentComponent "$region"
            }
            #endregion
        }
        else {
            fLogContent -fLogContent "Windows Time zone, culture, and regional settings configurations not defined in configuration file" -fLogContentComponent "$region" -fLogContentType 2
            fLogContent -fLogContent "Windows Time zone, culture, and regional settings not re-configured" -fLogContentComponent "$region"
        }
        #region :: Configure Set Time Zone Automatically
        if ($($config.windowsTCR.settings.SetTimeZoneAutomatically) -eq $true) {
            try {
                fLogContent -fLogContent "Set time zone automatically is enabled" -fLogContentComponent "$region"
                #region :: Configure Set Time Zone Automatically - Service
                fLogContent -fLogContent "adding HKLM:\System\CurrentControlSet\Services\tzautoupdate [REG_DWORD] Start ""3""" -fLogContentComponent "$region"
                fRegistryItem -task "add" -froot "HKLM" -fpath "System\CurrentControlSet\Services\tzautoupdate" -fname "Start" -fpropertyType "REG_DWORD" -fvalue "3"
                #endregion
                #region :: Configure Set Time Zone Automatically - User Consent
                fLogContent -fLogContent "adding HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location [REG_SZ] Value ""Allow""" -fLogContentComponent "$region"
                fRegistryItem -task "add" -froot "HKLM" -fpath "Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -fname "Value" -fpropertyType "REG_SZ" -fvalue "Allow"
                #endregion
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            Finally {}
        }
        else {
            fLogContent -fLogContent "Set time zone automatically is disabled" -fLogContentComponent "$region"
        }
        #endregion
        #region :: Configure Windows NTP server
        if ($($config.windowsTCR.settings.setNTPServer) -eq $true) {
            fLogContent -fLogContent "Configuring NTP Server is enabled" -fLogContentComponent "$region"
            try {
                If ($($config.windowsTCR.settings.setNTPServerPeerlist) -ge 1) {
                    fLogContent -fLogContent "> NTP Server peer list contains $($($config.windowsTCR.settings.setNTPServerPeerlist).Count) peer(s)" -fLogContentComponent "$region"
                    foreach ($NTPServer in $($config.windowsTCR.settings.setNTPServerPeerlist)) { 
                        #write-host "Host: $NTPServer"
                        $NTPServerList += "$NTPServer "
                    }
                    fLogContent -fLogContent "> NTP Server peer list: $NTPServerList" -fLogContentComponent "$region"
                    fLogContent -fLogContent "> Configuring NTP Server settings" -fLogContentComponent "$region"
                    if ($((Get-Service -Name w32time -ErrorAction SilentlyContinue).Status) -eq "Running") {
                        fLogContent -fLogContent "> Windows Time service is started" -fLogContentComponent "$region"
                    }
                    else {
                        fLogContent -fLogContent "> Windows Time service is stopped, attemting to start the service" -fLogContentComponent "$region"
                        start-service -Name w32time 
                    }
                    Start-Process -FilePath "$($env:Windir)\System32\w32tm.exe" -ArgumentList "/config /update /manualpeerlist:""$($NTPServerList.trim())"" /syncfromflags:MANUAL" -NoNewWindow -RedirectStandardOutput $false -RedirectStandardError $false -Wait
                }
                else {
                    fLogContent -fLogContent "> NTP Server peer list is empty" -fLogContentComponent "$region"
                }
                fLogContent -fLogContent "> Restarting Windows Time service" -fLogContentComponent "$region"
                Restart-Service -Name w32time -Force
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
                if ($exitOnError) {
                    exit 1
                }
            }
            Finally {}
            fLogContent -fLogContent "> Configuring NTP Server is finished" -fLogContentComponent "$region"
        }
        else {
            fLogContent -fLogContent "Configuring NTP Server is disabled" -fLogContentComponent "$region"
        }
        #endregion
        fLogContent -fLogContent "Windows Time zone, culture, and regional settings manager finished" -fLogContentComponent "$region"
    }
    else {
        fLogContent -fLogContent "Windows Time zone, culture, and regional settings manager is disabled" -fLogContentComponent "$region"
    }
    #endregion
    #
    #region :: metadata
    $region = "metadata"
    fLogContent -fLogContent "METADATA ITEMS" -fLogContentComponent "$region"
    if ($($config.metadata.enabled) -eq $true) {
        fLogContent -fLogContent "Metadata items is enabled" -fLogContentComponent "$region"
        switch ($($config.metadata.installBehavior).ToUpper()) {
            "SYSTEM" {
                $metadataRoot = "HKLM"
            }
            "USER" {
                $metadataRoot = "HKCU"
            }
            Default {
                fLogContent -fLogContent "ERROR: Processing metadata items failed" -fLogContentComponent "$region" -fLogContentType 3
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
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "$region" -fLogContentType 3
            if ($exitOnError) {
                exit 1
            }
        }
        finally {}
        #endregion
        fLogContent -fLogContent "Metadata items finished" -fLogContentComponent "$region"
    }
    else {
        fLogContent -fLogContent "Metadata items is disabled" -fLogContentComponent "$region"
    }
    #endregion
}
end {
    #region :: resetting run Preference
    $region = "resetting"
    $ProgressPreference = $envProgressPreference
    $WarningPreference = $envWarningPreference
    #endregion
    #region :: reboot
    $region = "reboot"
    fLogContent -fLogContent "Require reboot: $requireReboot" -fLogContentComponent "$region"
    #endregion
    #region :: cleaning-up
    $region = "clean-up"
    fLogContent -fLogContent "Finishing up..." -fLogContentComponent "$region"
    fLogContent -fLogContent "Cleaning up environment" -fLogContentComponent "$region"
    #endregion
}
#
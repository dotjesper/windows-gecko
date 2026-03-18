<# PSScriptInfo
.VERSION 1.5.2
.GUID 10E1CBFB-EBAF-4329-87C1-225132847F61
.AUTHOR Jesper Nielsen (@dotjesper)
.COMPANYNAME dotjesper.com
.COPYRIGHT © 2024-2026 dotjesper.com. All rights reserved.
.TAGS windows powershell windows-11 branding microsoft-intune windows-autopilot endpoint-management dsc desired-state-configuration winget
.LICENSEURI https://github.com/dotjesper/windows-gecko/blob/main/LICENSE
.PROJECTURI https://github.com/dotjesper/windows-gecko/
.ICONURI
.EXTERNALSCRIPTDEPENDENCIES
.REQUIREDSCRIPTS
.RELEASENOTES https://github.com/dotjesper/windows-gecko/wiki/release-notes/
#>
<#
.SYNOPSIS
    Windows gecko - Automated Windows Desired State Configuration for Modern Endpoint Management

.DESCRIPTION
    Windows gecko is a comprehensive PowerShell-based solution designed to deliver consistent desired state configurations to Windows 11 devices.

    Primarily designed for Windows Autopilot scenarios, Windows gecko can be seamlessly integrated into traditional deployment methods such as Operating System Deployment (OSD),
    Microsoft Intune Win32 apps, or manual execution for testing and validation purposes.

    The script provides a configuration-driven approach, utilizing JSON files to define all settings and behaviors, making it highly flexible and maintainable for enterprise environments.

    Current features:
    - WindowsApps: Remove Windows In-box Apps and Store Apps.
    - WindowsBranding: Configure OEM information and Registration.
    - WindowsConfig: Configure Windows using WinGet Configuration [In development].
    - WindowsFeatures: Enable and/or disable Windows features and optional features.
    - WindowsGroups: Add accounts to local groups [In review].
    - WindowsFiles: Copy file(s) to device from payload package.
    - WindowsRegistry: Modify Windows registry entries (add, change, or remove).
    - WindowsRun: Run local executables and/or download and run executables.
    - WindowsServices: Configure/reconfigure Windows Services.
    - WindowsScheduledTasks: Configure/reconfigure Windows Scheduled Tasks [In development].
    - WindowsTCR: Windows Time zone, culture, and regional settings manager [In preview].

    For sample configuration files, documentation, and to follow the latest development progress, visit the project site at:
    https://github.com/dotjesper/windows-gecko/

.NOTES
    Author:   Jesper Nielsen (@dotjesper)
    Website:  https://github.com/dotjesper/windows-gecko
    Version:  1.5.2
    Updated:  2026-03-15
    ---
    LEGAL DISCLAIMER

    This PowerShell script is provided "as-is" without warranty of any kind, either expressed or implied, including but not limited to
    the implied warranties of merchantability and fitness for a particular purpose. The author(s) and contributor(s) do not warrant that
    the functions contained in the script will meet your requirements or that the operation of the script will be uninterrupted or error-free.

    In no event shall the author(s) or contributor(s) be held liable for any direct, indirect, incidental, special, exemplary, or
    consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits;
    or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including
    negligence or otherwise) arising in any way out of the use of this script, even if advised of the possibility of such damage.

    IMPORTANT: It is strongly recommended to thoroughly test this script in a non-production environment before deploying to production
    systems. The script may require modification to fit your specific environment and requirements. By using this script, you acknowledge
    that you have read this disclaimer, understand it, and agree to be bound by its terms. You assume all risks and responsibilities
    associated with the use of this script.

.PARAMETER configFile
    Start script with the defined configuration file to be used for the task.
    Accepts a local file path or an HTTPS URL to a cloud-hosted configuration file, useful for testing and validation without local file dependencies.
    If no configuration file is defined, script will look for .\config.json. If the configuration is not found or invalid, the script will exit.

.PARAMETER CultureIdentifier
    Windows Time zone, culture, and regional settings value, allowing configuring culture, homelocation, and timezone from configuration file.
    Value must match windowsTCR.configurations.CID.[CID], e.g. "DEN", "565652" or any other value you prefer.

    See sample files for more examples.

.PARAMETER logFile
    Start script logging to the desired logFile.
    If no log file is defined, the script will default to log file within '%ProgramData%\Microsoft\IntuneManagementExtension\Logs' folder, file name <config.metadata.title>.log

    If the specified path is not writeable, the log file will automatically fall back to the '%TEMP%' folder.

.PARAMETER exitOnError
    If an error occurs, control if script should exit-on-error. Default value is $false.

.PARAMETER showProgress
    Show PowerShell progress bars during script execution. By default, progress bars are hidden as the script is designed to run silently in deployment scenarios.
    Progress bars only apply to specific sections that perform lengthy operations, such as downloading files or expanding archives.
    This parameter is primarily intended for interactive testing and troubleshooting purposes.

    For detailed runtime output, consider using -Verbose instead, as comprehensive logging is built into the script.

.PARAMETER disableLogging
    Disable writing to the log file. When specified, Write-Log entries are suppressed and only verbose output is available.
    This parameter is intended for interactive testing and development scenarios only. Default value is $false.

.PARAMETER uninstall
    Future parameter for use in Microsoft Intune package deployment scenarios. Default value is $false.

.EXAMPLE
    .\gecko.ps1

    Runs with default configuration file (.\config.json) and default logging to the IME logs folder.

.EXAMPLE
    .\gecko.ps1 -configFile ".\usercfg.json"

    Runs with a custom local configuration file.

.EXAMPLE
    .\gecko.ps1 -configFile ".\usercfg.json" -CultureIdentifier "DEN"

    Runs with a custom configuration file and applies the "DEN" culture settings.

.EXAMPLE
    .\gecko.ps1 -configFile ".\usercfg.json" -logFile ".\usercfg.log" -Verbose

    Runs with a custom configuration file, a custom log file, and verbose output enabled.

.EXAMPLE
    .\gecko.ps1 -configFile "https://<URL>/config.json"

    Runs with a cloud-hosted configuration file downloaded over HTTPS.

.EXAMPLE
    .\gecko.ps1 -configFile ".\configC.json" -DisableLogging -Verbose

    Runs with logging disabled and verbose output only - useful for interactive testing.

#>
#requires -version 5.1
[CmdletBinding(SupportsShouldProcess)]
param (

    [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "Configuration file to be used for the task. Can be a local path or HTTPS URL.")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ $_.StartsWith("https://", "CurrentCultureIgnoreCase") -or (Test-Path $_) })]
    [Alias("Config", "c")]
    [string]$configFile = ".\config.json",

    [Parameter(Mandatory = $false, Position = 1, ValueFromPipelineByPropertyName = $true, HelpMessage = "Log file path to be used for the task. If not specified, defaults to IME logs folder.")]
    [Alias("Log", "l")]
    [string]$logFile = "",

    [Parameter(Mandatory = $false, Position = 2, ValueFromPipelineByPropertyName = $true, HelpMessage = "Windows Time zone, culture, and regional settings value, allowing configuration of culture, home location, and timezone from configuration file.")]
    [ValidatePattern('^[a-zA-Z0-9_-]+$')]
    [Alias("CID", "Culture", "Region")]
    [string]$CultureIdentifier,

    [Parameter(Mandatory = $false, HelpMessage = "If an error occurs, control whether script should exit on error. Default value is false.")]
    [Alias("StopOnError")]
    [switch]$exitOnError,

    [Parameter(Mandatory = $false, HelpMessage = "Show PowerShell progress bars. By default, progress bars are hidden.")]
    [Alias("Progress", "p")]
    [switch]$showProgress,

    [Parameter(Mandatory = $false, HelpMessage = "Disable writing to the log file. Only verbose output is available when specified.")]
    [Alias("NoLog")]
    [switch]$disableLogging,

    [Parameter(Mandatory = $false, HelpMessage = "Future parameter for use in Microsoft Intune package deployment scenarios. Default value is false.")]
    [Alias("u")]
    [switch]$uninstall
)
begin {
    #region :: Environment
    [version]$ScriptVersion = '1.5.2'
    Set-Variable -Name 'ScriptVersion' -Value $ScriptVersion -Option ReadOnly -Scope Script
    Set-StrictMode -Version Latest

    # Welcome line
    Write-Verbose -Message "## Windows gecko v$($script:ScriptVersion) - Windows desired state configuration"
    #endregion

    #region :: Parse configuration file
    if ($configFile.StartsWith("https://","CurrentCultureIgnoreCase")) {
        Write-Verbose -Message "Downloading configuration file [$configFile]"
        try {
            $previousProgressPreference = $global:ProgressPreference
            $global:ProgressPreference = "SilentlyContinue"
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
        finally {
            $global:ProgressPreference = $previousProgressPreference
        }
    }
    else {
        Write-Verbose -Message "Loading configuration file[$configFile]"
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
            Write-Output -InputObject "Go to https://github.com/dotjesper/windows-gecko/ to download sample configuration files"
            exit 1
        }
    }
    #endregion

    #region :: Environment configurations
    [bool]$requireReboot = $config.runConditions.requireReboot
    [string]$envProgressPreference = $global:ProgressPreference
    [string]$envWarningPreference = $WarningPreference
    if (-not $showProgress) {
        # Set at global scope so script module functions (e.g. Expand-Archive) also inherit the suppression.
        # In PS 5.1, script module functions see $global:ProgressPreference, not the caller's local scope.
        $global:ProgressPreference = "SilentlyContinue"
        $WarningPreference = "SilentlyContinue"
    }
    # CLM-compatible alternatives for blocked .NET calls
    [bool]$script:IsConstrainedLanguageMode = $ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage"
    [int]$script:CurrentOSBuild = [int](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuild").CurrentBuild
    [bool]$script:Is64BitProcess = [IntPtr]::Size -eq 8
    # Default User registry hive constants
    [string]$script:defaultUserRegistryFile = "$env:SystemDrive\Users\Default\NTuser.dat"
    [string]$script:defaultUserRegistryRoot = "HKLM"
    [string]$script:defaultUserRegistryKey = ".DEFAULTUSER"
    [bool]$script:defaultUserHiveLoaded = $false
    #endregion

    #region :: log file validation and setup
    if ($config.metadata.title) {
        [string]$script:logPackageName = "$($config.metadata.title -replace '[^a-zA-Z0-9]','-')"
        [string]$logFilePath = "$($Env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\$script:logPackageName.log"
    }
    else {
        [string]$script:logPackageName = "$((Split-Path -Leaf $MyInvocation.MyCommand.Definition) -replace '\.[^.]+$' -replace '[^a-zA-Z0-9]','-')"
        [string]$logFilePath = "$($Env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\$script:logPackageName.log"
    }
    if (-not $disableLogging) {
        if ($logFile.Length -gt 0) {
            $logFileFullPath = Resolve-Path $logFile -ErrorAction SilentlyContinue -ErrorVariable _frperror
            if ($logFileFullPath) {
                [string]$logFilePath = $logFileFullPath
            }
            else {
                [string]$logFilePath = $_frperror[0].TargetObject
            }
        }

        # Test log file writability (CLM-compatible, matching log encoding)
        try {
            Add-Content -Path $logFilePath -Value "" -Encoding "UTF8" -ErrorAction Stop
            Write-Verbose -Message "Log file is writable"
        }
        catch {
            Write-Warning -Message "Unable to write to output file $logFilePath"
            Write-Verbose -Message $_.Exception.Message
            Write-Verbose -Message "Redirecting output file to '$($Env:Temp)' folder"
            [string]$logFilePath = "$($Env:Temp)\$script:logPackageName.log"
        }
    }
    #endregion

    #region :: Functions
    function Write-Log {
        <#
        .SYNOPSIS
            Write formatted log entries to a CMTrace/Intune-compatible log file.
        .DESCRIPTION
            Writes log entries with CMTrace and Microsoft Intune Management Extension compatible formatting.
            Supports different log levels (Info, Warning, Error) and component-based logging.
        .PARAMETER Message
            The log message to write to the log file.
        .PARAMETER Component
            The component or section of the script generating the log entry.
        .PARAMETER Severity
            The severity level of the log entry:
            1: Information (Default)
            2: Warning
            3: Error
        .PARAMETER logFile
            Optional. Overrides the default log file path for this specific entry.
        .EXAMPLE
            Write-Log -Message "Starting Windows configuration" -Component "windowsApps"
        .EXAMPLE
            Write-Log -Message "Failed to configure feature" -Component "WindowsFeatures" -Severity 3
        #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, HelpMessage = "Log message to write.")]
            [Alias("LogMessage", "Text", "fLogContent")]
            [string]$Message,

            [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Component or section generating the log entry.")]
            [Alias("Source", "Area", "fLogContentComponent")]
            [string]$Component = "",

            [Parameter(Mandatory = $false, HelpMessage = "Log severity: 1=Info, 2=Warning, 3=Error")]
            [ValidateSet(1, 2, 3)]
            [Alias("LogLevel", "Type", "fLogContentType")]
            [int]$Severity = 1,

            [Parameter(Mandatory = $false, HelpMessage = "Override the default log file path.")]
            [Alias("fLogContentfn")]
            [string]$logFile = $logFilePath
        )
        process {
            if ($disableLogging) {
                Write-Verbose -Message $Message
                return
            }
            try {
                # Get timestamp per message for accurate logging in pipeline scenarios
                $timestamp = Get-Date

                # Build CMTrace-compatible log entry (CLM-compatible: use PID instead of thread ID)
                if ($script:IsConstrainedLanguageMode) {
                    $threadId = $PID
                }
                else {
                    try {
                        $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                    }
                    catch {
                        $threadId = $PID
                    }
                }

                # Build log entry with proper escaping for CMTrace/IME compatibility
                $logEntry = "<![LOG[[$script:logPackageName] $Message]LOG]!>" +
                            "<time=""$($timestamp.ToString('HH:mm:ss.fffffff'))"" " +
                            "date=""$($timestamp.ToString('MM-dd-yyyy'))"" " +
                            "component=""$Component"" context="""" " +
                            "type=""$Severity"" thread=""$threadId"" file="""">"

                # Write to log file with UTF8 encoding
                Add-Content -Path $logFile -Value $logEntry -Encoding "UTF8" -ErrorAction "Stop"

                # Output to verbose stream
                Write-Verbose -Message $Message
            }
            catch {
                # Fallback: Write to warning stream but don't exit entire script
                Write-Warning "Failed to write to log file: $($_.Exception.Message)"
            }
        }
    }

    function Set-RegistryItem {
        <#
        .SYNOPSIS
            Manages Windows registry entries with support for add, update, and remove operations.
        .DESCRIPTION
            This function modifies Windows registry entries including HKDU (Default User) support.
            Automatically creates registry paths if they don't exist. Supports -WhatIf and -Confirm.
        .PARAMETER Action
            The operation to perform: 'Add' (creates or updates) or 'Remove' (deletes)
        .PARAMETER Root
            Registry root hive: HKCR, HKCU, HKDU, HKLM, HKU
        .PARAMETER Path
            Registry path without the root, e.g., 'Software\Microsoft\Windows\CurrentVersion'
        .PARAMETER Name
            Registry value name. Use '*' with Remove to delete entire key.
        .PARAMETER PropertyType
            Registry value type: String, DWord, QWord, Binary, MultiString, ExpandString
        .PARAMETER Value
            The value to set for the registry entry
        .PARAMETER Force
            Force the operation even if the value already matches
        .EXAMPLE
            Set-RegistryItem -Action Add -Root HKLM -Path 'Software\MyApp' -Name 'Version' -PropertyType DWord -Value 1
        .EXAMPLE
            Set-RegistryItem -Action Remove -Root HKCU -Path 'Software\MyApp' -Name 'TempValue'
        .EXAMPLE
            Set-RegistryItem -Action Remove -Root HKLM -Path 'Software\MyApp' -Name '*'
        #>
        [CmdletBinding(SupportsShouldProcess)]
        param (
            [Parameter(Mandatory = $true, Position = 0)]
            [ValidateSet('Add', 'Remove')]
            [string]$Action,

            [Parameter(Mandatory = $true, Position = 1)]
            [ValidateSet('HKCR', 'HKCU', 'HKDU', 'HKLM', 'HKU')]
            [string]$Root,

            [Parameter(Mandatory = $true, Position = 2)]
            [ValidateNotNullOrEmpty()]
            [string]$Path,

            [Parameter(Mandatory = $true, Position = 3)]
            [ValidateNotNullOrEmpty()]
            [string]$Name,

            [Parameter(Mandatory = $false)]
            [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord',
                        'REG_SZ', 'REG_EXPAND_SZ', 'REG_BINARY', 'REG_DWORD', 'REG_MULTI_SZ', 'REG_QWORD')]
            [string]$PropertyType = 'String',

            [Parameter(Mandatory = $false)]
            [object]$Value,

            [Parameter(Mandatory = $false)]
            [switch]$Force
        )
        begin {
            # Normalize property type
            $normalizedPropertyType = switch ($PropertyType) {
                'REG_SZ'        { 'String' }
                'REG_EXPAND_SZ' { 'ExpandString' }
                'REG_BINARY'    { 'Binary' }
                'REG_DWORD'     { 'DWord' }
                'REG_MULTI_SZ'  { 'MultiString' }
                'REG_QWORD'     { 'QWord' }
                default         { $PropertyType }
            }

            # Sanitize path - remove leading/trailing backslashes (CLM-compatible: use -replace operator instead of .Trim() method)
            $Path = $Path -replace '^\\+|\\+$'

            # Handle HKDU (Default User) special case
            if ($Root -eq 'HKDU') {
                Write-Log -Message "Converting HKDU to HKLM:\$script:defaultUserRegistryKey" -Component 'Set-RegistryItem'
                $Root = 'HKLM'
                $Path = "$script:defaultUserRegistryKey\$Path"
            }

            $registryPath = "$($Root):\$Path"
        }
        process {
            try {
                switch ($Action) {
                    'Add' {
                        # Ensure path exists
                        if (-not (Test-Path -Path $registryPath)) {
                            # CLM-compatible: $PSCmdlet.ShouldProcess() fails in Constrained Language Mode
                            if ($script:IsConstrainedLanguageMode -or $PSCmdlet.ShouldProcess($registryPath, "Create registry key")) {
                                Write-Log -Message "Creating registry path [$registryPath]" -Component 'Set-RegistryItem'
                                New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
                            }
                        }

                        # Convert value based on type (CLM-compatible)
                        $convertedValue = switch ($normalizedPropertyType) {
                            'Binary' {
                                if ($Value -is [string]) {
                                    if ($script:IsConstrainedLanguageMode) {
                                        Write-Log -Message "Binary registry values require Full Language mode" -Component 'Set-RegistryItem' -Severity 2
                                        $null
                                    }
                                    else {
                                        [byte[]]($Value.Split(',') | ForEach-Object {
                                            if ($_ -match '^0x') { [Convert]::ToByte($_, 16) }
                                            else { [Convert]::ToByte($_.Trim(), 10) }
                                        })
                                    }
                                } else { $Value }
                            }
                            'QWord' {
                                [Int64]$Value
                            }
                            'DWord' {
                                [Int32]$Value
                            }
                            'MultiString' {
                                if ($Value -is [string]) {
                                    [string[]](($Value -split ',') | ForEach-Object { $_ -replace '^\s+|\s+$' })
                                }
                                else {
                                    [string[]]$Value
                                }
                            }
                            default { $Value }
                        }

                        # Get current value
                        $currentValue = (Get-ItemProperty -Path $registryPath -Name $Name -ErrorAction SilentlyContinue).$Name

                        # Check if update is needed (proper array comparison)
                        $needsUpdate = $Force -or ($null -eq $currentValue)
                        if (-not $needsUpdate -and $null -ne $currentValue) {
                            if ($convertedValue -is [array]) {
                                $needsUpdate = $null -ne (Compare-Object $currentValue $convertedValue -SyncWindow 0)
                            }
                            else {
                                $needsUpdate = $currentValue -ne $convertedValue
                            }
                        }

                        if ($needsUpdate) {
                            # CLM-compatible: $PSCmdlet.ShouldProcess() fails in Constrained Language Mode
                            if ($script:IsConstrainedLanguageMode -or $PSCmdlet.ShouldProcess("$registryPath\$Name", "Set value to '$convertedValue'")) {
                                Write-Log -Message "Setting [$registryPath] $Name = $convertedValue (Type: $normalizedPropertyType)" -Component 'Set-RegistryItem'
                                New-ItemProperty -Path $registryPath -Name $Name -PropertyType $normalizedPropertyType -Value $convertedValue -Force -ErrorAction Stop | Out-Null
                                Write-Log -Message "Registry value set successfully" -Component 'Set-RegistryItem'
                            }
                        }
                        else {
                            Write-Log -Message "Registry value already configured" -Component 'Set-RegistryItem'
                        }
                    }

                    'Remove' {
                        if ($Name -eq '*') {
                            # Remove entire key
                            if (Test-Path -Path $registryPath) {
                                # CLM-compatible: $PSCmdlet.ShouldProcess() fails in Constrained Language Mode
                                if ($script:IsConstrainedLanguageMode -or $PSCmdlet.ShouldProcess($registryPath, "Remove registry key")) {
                                    Write-Log -Message "Removing registry key [$registryPath]" -Component 'Set-RegistryItem'
                                    Remove-Item -Path $registryPath -Recurse -Force -ErrorAction Stop
                                }
                            }
                            else {
                                Write-Log -Message "Registry key not found [$registryPath]" -Component 'Set-RegistryItem'
                            }
                        }
                        else {
                            # Remove specific value
                            $existingProp = Get-ItemProperty -Path $registryPath -Name $Name -ErrorAction SilentlyContinue
                            if ($existingProp) {
                                # CLM-compatible: $PSCmdlet.ShouldProcess() fails in Constrained Language Mode
                                if ($script:IsConstrainedLanguageMode -or $PSCmdlet.ShouldProcess("$registryPath\$Name", "Remove registry value")) {
                                    Write-Log -Message "Removing registry value [$registryPath] $Name" -Component 'Set-RegistryItem'
                                    Remove-ItemProperty -Path $registryPath -Name $Name -Force -ErrorAction Stop
                                }
                            }
                            else {
                                Write-Log -Message "Registry value not found [$registryPath] $Name" -Component 'Set-RegistryItem'
                            }
                        }
                    }
                }
            }
            catch {
                Write-Log -Message "ERROR: $($_.Exception.Message)" -Component 'Set-RegistryItem' -Severity 3
                if ($exitOnError) {
                    throw
                }
            }
        }
    }

    function Mount-DefaultUserHive {
        <#
        .SYNOPSIS
            Loads the Default User registry hive (NTuser.dat) into HKLM.
        .DESCRIPTION
            Mounts the Default User NTuser.dat file into HKLM under the configured key.
            Tracks state via $script:defaultUserHiveLoaded to prevent double-loading.
        #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $false)]
            [string]$Component = 'Mount-DefaultUserHive'
        )
        if ($script:defaultUserHiveLoaded) {
            Write-Log -Message "Default User Registry hive already loaded" -Component $Component
            return $true
        }
        Write-Log -Message "Loading Default User registry hive ($script:defaultUserRegistryFile)" -Component $Component
        try {
            $processResult = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "LOAD $script:defaultUserRegistryRoot\$script:defaultUserRegistryKey $script:defaultUserRegistryFile" -WindowStyle Hidden -PassThru -Wait
            if ($processResult.ExitCode -eq 0) {
                Write-Log -Message "Successfully loaded Default User Registry hive as '$script:defaultUserRegistryRoot\$script:defaultUserRegistryKey'" -Component $Component
                $script:defaultUserHiveLoaded = $true
                return $true
            }
            else {
                Write-Log -Message "Failed loading Default User Registry hive as '$script:defaultUserRegistryRoot\$script:defaultUserRegistryKey'" -Component $Component -Severity 3
                return $false
            }
        }
        catch {
            Write-Log -Message "ERROR: $($_.Exception.Message)" -Component $Component -Severity 3
            return $false
        }
    }

    function Dismount-DefaultUserHive {
        <#
        .SYNOPSIS
            Unloads the Default User registry hive from HKLM.
        .DESCRIPTION
            Unmounts the previously loaded Default User NTuser.dat from HKLM.
            Retries up to 3 times with 15-second intervals to allow handles to be released.
        #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $false)]
            [string]$Component = 'Dismount-DefaultUserHive'
        )
        if (-not $script:defaultUserHiveLoaded) {
            Write-Log -Message "Default User Registry hive is not loaded, skipping unload" -Component $Component
            return
        }
        Write-Log -Message "Unloading Default User Registry hive" -Component $Component
        [int]$counter = 0
        do {
            Write-Log -Message "Sleeping 15 seconds before attempting unloading Default User Registry hive" -Component $Component
            Start-Sleep -Seconds 15
            # Force garbage collection to release registry handles (CLM-compatible)
            if (-not $script:IsConstrainedLanguageMode) { try { [gc]::Collect() } catch {} }
            $processResult = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "UNLOAD $script:defaultUserRegistryRoot\$script:defaultUserRegistryKey" -WindowStyle Hidden -PassThru -Wait
            $counter++
            Write-Log -Message "Unloading Default User Registry hive attempted [ $($processResult.ExitCode) | $($counter) ]" -Component $Component
        }
        While (($processResult.ExitCode -gt 0) -and ($counter -le 3))
        if ($processResult.ExitCode -eq 0) {
            Write-Log -Message "Successfully unloaded Default User Registry hive" -Component $Component
            $script:defaultUserHiveLoaded = $false
        }
        else {
            Write-Log -Message "Failed unloading Default User Registry hive" -Component $Component -Severity 3
        }
    }

    function Test-OSBuildInRange {
        <#
        .SYNOPSIS
            Tests if the current OS build is within a specified range.
        .DESCRIPTION
            Validates if the current Windows build number falls within the specified
            minimum and maximum build range. A value of 0 means no restriction.
        .PARAMETER MinOSBuild
            Minimum OS build number. 0 means no minimum restriction.
        .PARAMETER MaxOSBuild
            Maximum OS build number. 0 means no maximum restriction.
        .PARAMETER ItemDescription
            Description of the item being validated for logging purposes.
        .PARAMETER Component
            Component name for logging.
        .EXAMPLE
            if (Test-OSBuildInRange -MinOSBuild 22000 -MaxOSBuild 0 -ItemDescription "Feature X" -Component "windowsFeatures") { ... }
        #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $false)]
            [int]$MinOSBuild = 0,

            [Parameter(Mandatory = $false)]
            [int]$MaxOSBuild = 0,

            [Parameter(Mandatory = $false)]
            [string]$ItemDescription = "",

            [Parameter(Mandatory = $false)]
            [string]$Component = "Test-OSBuildInRange"
        )
        # Apply defaults: 0 means no restriction (use current build)
        $effectiveMin = if ($MinOSBuild -eq 0) { $script:CurrentOSBuild } else { $MinOSBuild }
        $effectiveMax = if ($MaxOSBuild -eq 0) { $script:CurrentOSBuild } else { $MaxOSBuild }

        Write-Log -Message "Min OS build: $(if ($MinOSBuild -eq 0) { 'not specified' } else { $MinOSBuild })" -Component $Component
        Write-Log -Message "Max OS build: $(if ($MaxOSBuild -eq 0) { 'not specified' } else { $MaxOSBuild })" -Component $Component

        $inRange = ($script:CurrentOSBuild -ge $effectiveMin -and $script:CurrentOSBuild -le $effectiveMax)
        if (-not $inRange -and $ItemDescription) {
            Write-Log -Message "Item $ItemDescription entry not for this OS build" -Component $Component
        }
        return $inRange
    }

    function Expand-EnvironmentVariables {
        <#
        .SYNOPSIS
            Expands Windows environment variables in a CLM-compatible manner.
        .DESCRIPTION
            Expands environment variables like %TEMP% in a path string.
            Returns $null if running in Constrained Language Mode (CLM) since
            [Environment]::ExpandEnvironmentVariables is blocked.
        .PARAMETER Path
            The path string containing environment variables to expand.
        .PARAMETER Component
            Component name for logging.
        .EXAMPLE
            $expandedPath = Expand-EnvironmentVariables -Path "%TEMP%\file.txt" -Component "windowsFiles"
        #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$Path,

            [Parameter(Mandatory = $false)]
            [string]$Component = "Expand-EnvironmentVariables"
        )
        # Check if path contains environment variables
        if ($Path -notmatch "%\S+%") {
            return $Path
        }

        # CLM blocks [Environment]::ExpandEnvironmentVariables
        if ($script:IsConstrainedLanguageMode) {
            Write-Log -Message "Windows Environment Variables is currently supported using Full Language mode only" -Component $Component -Severity 2
            Write-Log -Message "Windows Environment Variables found, resolving $Path terminated" -Component $Component
            return $null
        }

        Write-Log -Message "Windows Environment Variables found, resolving $Path" -Component $Component
        $expandedPath = [Environment]::ExpandEnvironmentVariables($Path)
        Write-Log -Message "Windows Environment Variables resolved to $expandedPath" -Component $Component
        return $expandedPath
    }
    #endregion

    <#
    Constrained Language Mode (CLM) Compatibility Notes
    ====================================================
    This script is designed to work in both Full Language Mode and Constrained Language Mode.
    The following .NET calls are blocked in CLM and require workarounds:

    - [Convert]::*                  -> Use PowerShell operators or native cmdlets
    - [System.IO.Path]::*           -> Use Split-Path, Join-Path cmdlets
    - [Environment]::*              -> Use $env: variables or skip functionality
    - [Threading.Thread]::*         -> Use $PID as fallback for thread ID
    - [gc]::Collect()               -> Skip garbage collection
    - String methods (.Trim(), etc) -> Use -replace operator
    - $PSCmdlet.ShouldProcess()     -> Check $script:IsConstrainedLanguageMode first

    Allowed type accelerators in CLM: [int], [string], [bool], [array], [version], [IntPtr]

    Binary registry values (REG_BINARY) require [Convert] and are skipped in CLM with a warning.
    #>

    #region :: logFile environment entries
    $region = "environment"
    try {
        # Log configuration metadata and environment information
        Write-Log -Message "ENVIRONMENT INFORMATION" -Component "$region"
        Write-Log -Message "Script name: $($MyInvocation.MyCommand.Name)" -Component "$region"
        Write-Log -Message "Script version: $($script:ScriptVersion)" -Component "$region"
        if ($disableLogging) {
            Write-Log -Message "Logging disabled" -Component "$region"
        }
        else {
            Write-Log -Message "Log file: $($logFilePath)" -Component "$region"
        }

        # Configuration metadata
        Write-Log -Message "Configuration file name: $($configFile)" -Component "$region"
        Write-Log -Message "Configuration file title: $($config.metadata.title)" -Component "$region"
        Write-Log -Message "Configuration file description: $($config.metadata.description)" -Component "$region"
        Write-Log -Message "Configuration file developer: $($config.metadata.developer)" -Component "$region"
        Write-Log -Message "Configuration file version: $($config.metadata.version) | $($config.metadata.date)" -Component "$region"

        # Build command line arguments string from bound parameters (CLM-compatible: use .Keys instead of .GetEnumerator())
        [string]$commandLineArguments = ($MyInvocation.BoundParameters.Keys | ForEach-Object {
            $key = $_
            $value = $MyInvocation.BoundParameters[$key]
            switch ($value) {
                { $_ -is [System.Management.Automation.SwitchParameter] } { if ($_.IsPresent) { "-$key" } }
                { $_ -is [bool] }   { "-$key `$$_" }
                { $_ -is [string] } { "-$key `"$_`"" }
                { $_ -is [array] }  { "-$key @($($_ -join ','))" }
                default             { "-$key $_" }
            }
        }) -join ' '

        Write-Log -Message "Command line: .\$($MyInvocation.MyCommand.Name) $commandLineArguments" -Component "$region"
        Write-Log -Message "Run script in 64 bit PowerShell: $($config.runConditions.runScriptIn64bitPowerShell)" -Component "$region"
        Write-Log -Message "Running 64 bit PowerShell: $script:Is64BitProcess" -Component "$region"

        # In Constrained Language Mode, certain .NET calls are blocked, so we use environment variables as a fallback for user information
        if ($($ExecutionContext.SessionState.LanguageMode) -eq "FullLanguage") {
            Write-Log -Message "Running elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" -Component "$region"
            Write-Log -Message "Detected user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Component "$region"
        }
        else {
            Write-Log -Message "Detected user: $($Env:USERNAME)" -Component "$region"
        }

        # Log additional environment information
        Write-Log -Message "Detected language mode: $($ExecutionContext.SessionState.LanguageMode)" -Component "$region"
        Write-Log -Message "Detected culture name: $((Get-Culture).Name)" -Component "$region"
        Write-Log -Message "Detected keyboard layout Id: $((Get-Culture).KeyboardLayoutId)" -Component "$region"
        Write-Log -Message "Detected computer name: $env:COMPUTERNAME" -Component "$region"
        Write-Log -Message "Detected OS build: $script:CurrentOSBuild" -Component "$region"
        Write-Log -Message "Detected Windows UI culture name: $((Get-UICulture).Name)" -Component "$region"

        # Network connectivity probe (lightweight, uses Windows NCSI endpoint)
        if ($config.runConditions.networkProbe -eq $true) {
            # Validate networkProbeCount configuration, default to 3 probes if not specified
            if ($config.runConditions.networkProbeCount -gt 0) {
                [int]$networkProbeCount = $config.runConditions.networkProbeCount
            }
            else {
                [int]$networkProbeCount = 3
            }

            # Perform network probes to Windows NCSI endpoint and log results
            try {
                $probeUrl = "http://www.msftconnecttest.com/connecttest.txt"
                [array]$probeTimes = @()
                for ($i = 1; $i -le $networkProbeCount; $i++) {
                    $probeStart = Get-Date
                    $probeResult = Invoke-WebRequest -Uri $probeUrl -UseBasicParsing -TimeoutSec 10 -Verbose:$false -ErrorAction Stop
                    $probeElapsed = (Get-Date) - $probeStart
                    $probeTimes += $probeElapsed.TotalMilliseconds
                    Write-Log -Message "Detected network connectivity: probe $i connected ($($probeResult.StatusCode)) in $($probeElapsed.TotalMilliseconds.ToString('N0')) ms" -Component "$region"
                }
                $probeAverage = ($probeTimes | Measure-Object -Average).Average
                $probeRating = if ($probeAverage -lt 100) { "Fast" } elseif ($probeAverage -le 500) { "Moderate" } else { "Slow" }
                Write-Log -Message "Detected network connectivity: average $($probeAverage.ToString('N0')) ms ($probeRating) over $($probeTimes.Count) probes" -Component "$region"
            }
            catch {
                Write-Log -Message "Detected network connectivity: failed ($($_.Exception.Message))" -Component "$region" -Severity 2
            }
        }
        else {
            Write-Log -Message "Detected network connectivity: probe disabled" -Component "$region"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
        if ($exitOnError) {
            exit 1
        }
    }
    #endregion

    #region :: Check conditions
    $region = "conditions"
    if ($config.runConditions.runScriptIn64bitPowerShell -eq $true -and $script:Is64BitProcess -eq $false) {
        Write-Log -Message "Script must be run using 64-bit PowerShell" -Component "$region"
        try {
            Write-Log -Message "Script relaunching using 64-bit PowerShell" -Component "$region"
            Start-Process -FilePath "$env:windir\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList $("-ExecutionPolicy Bypass -File .\" + $($myInvocation.myCommand.name) + " " + $($commandLineArguments)) -Wait -NoNewWindow
            exit 0
        }
        catch {
            $errMsg = $_.Exception.Message
            Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
            if ($exitOnError) {
                exit 1
            }
        }
    }
    #endregion

}
process {
    #region :: windowsApps
    $region = "windowsApps"
    Write-Log -Message "WINDOWS APPS" -Component "$region"
    if ($config.windowsApps.enabled -eq $true) {
        Write-Log -Message "Windows Apps is enabled" -Component "$region"

        # Import Appx module for managing Windows Store apps, handle errors if module is not available.
        Import-Module -Name Appx -ErrorAction SilentlyContinue -Verbose:$false

        [array]$windowsApps = $config.windowsApps.apps
        if ($null -eq $windowsApps -or $windowsApps.Count -eq 0) {
            Write-Log -Message "No apps defined in configuration" -Component "$region"
        }
        else {
            foreach ($windowsApp in $windowsApps) {
                Write-Log -Message "Processing $($windowsApp.DisplayName)" -Component "$region"
                if ($windowsApp.Remove -ne $true -and $windowsApp.RemoveProvisionedPackage -ne $true) {
                    Write-Log -Message "$($windowsApp.DisplayName) configured to not remove, skipping" -Component "$region"
                    continue
                }

                #region :: Appx Package
                try {
                    [array]$AppxPackage = Get-AppxPackage -AllUsers -Name $($windowsApp.Name) -Verbose:$false
                    if ($AppxPackage) {
                        Write-Log -Message "$($windowsApp.DisplayName) is present" -Component "$region"
                        Write-Log -Message "$($windowsApp.DisplayName) is bundle: $($AppxPackage.IsBundle)" -Component "$region"
                        Write-Log -Message "$($windowsApp.DisplayName) is non-removable: $($AppxPackage.NonRemovable)" -Component "$region"
                        if ($($windowsApp.Remove) -eq $true) {
                            Write-Log -Message "$($windowsApp.DisplayName) is being removed from all users" -Component "$region"
                            Write-Log -Message "$($windowsApp.DisplayName) :: $($AppxPackage.Name)" -Component "$region"
                            Write-Log -Message "$($windowsApp.DisplayName) :: $($AppxPackage.PackageFullName)" -Component "$region"
                            Write-Log -Message "$($windowsApp.DisplayName) :: $($AppxPackage.PackageFamilyName)" -Component "$region"
                            Write-Log -Message "$($windowsApp.DisplayName) :: $($AppxPackage.Version)" -Component "$region"
                            try {
                                Remove-AppxPackage -AllUsers -Package "$($AppxPackage.PackageFullName)" -Verbose:$false | Out-Null
                            }
                            catch {
                                $errMsg = $_.Exception.Message
                                Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                                if ($exitOnError) {
                                    exit 1
                                }
                            }
                        }
                    }
                    else {
                        Write-Log -Message "$($windowsApp.Name) not present" -Component "$region"
                    }
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                #endregion

                #region :: Appx Provisioned Package
                if ($windowsApp.RemoveProvisionedPackage -eq $true -and $config.metadata.installBehavior -ne "SYSTEM") {
                    Write-Log -Message "Skipping provisioned package removal for $($windowsApp.DisplayName) - RemoveProvisionedPackage requires SYSTEM install behavior" -Component "$region" -Severity 2
                }
                elseif ($windowsApp.RemoveProvisionedPackage -eq $true) {
                try {
                    [array]$AppxProvisionedPackage = Get-AppxProvisionedPackage -Online -Verbose:$false | Where-Object { $_.DisplayName -eq $($windowsApp.Name) } | Select-Object "DisplayName", "Version", "PublisherId", "PackageName"
                    if ($AppxProvisionedPackage) {
                        Write-Log -Message "$($windowsApp.DisplayName) is present as provisioned app" -Component "$region"
                        Write-Log -Message "$($windowsApp.DisplayName), $($AppxProvisionedPackage.DisplayName)" -Component "$region"
                        Write-Log -Message "$($windowsApp.DisplayName), $($AppxProvisionedPackage.PackageName), $($AppxProvisionedPackage.Version)" -Component "$region"
                        Write-Log -Message "$($windowsApp.DisplayName) remove: $($windowsApp.RemoveProvisionedPackage)" -Component "$region"
                        if ($windowsApp.RemoveProvisionedPackage -eq $true) {
                            Write-Log -Message "$($AppxProvisionedPackage.DisplayName) is being removed" -Component "$region"
                            try {
                                Remove-AppxProvisionedPackage -Online -PackageName "$($AppxProvisionedPackage.PackageName)" -Verbose:$false | Out-Null
                            }
                            catch {
                                $errMsg = $_.Exception.Message
                                Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                                if ($exitOnError) {
                                    exit 1
                                }
                            }
                        }
                    }
                    else {
                        Write-Log -Message "$($windowsApp.DisplayName) is not present" -Component "$region"
                    }
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                }
                #endregion
            }
        }
        Write-Log -Message "Windows Apps completed" -Component "$region"
    }
    else {
        Write-Log -Message "Windows Apps is disabled" -Component "$region"
    }
    #endregion

    #region :: windowsBranding
    $region = "windowsBranding"
    Write-Log -Message "WINDOWS BRANDING" -Component "$region"
    if ($config.windowsBranding.enabled -eq $true) {
        Write-Log -Message "Windows branding is enabled" -Component "$region"

        # Validate install behavior
        if ($config.metadata.installBehavior -eq "SYSTEM") {

            #region :: OEM Information
            foreach ($OEMInformationItem in $config.windowsBranding.OEMInformationItems.PsObject.Properties) {
                if ([string]::IsNullOrEmpty($OEMInformationItem.Value)) {
                    Write-Log -Message "$($OEMInformationItem.Name) value is not defined" -Component "$region" -Severity 2
                }
                else {
                    Write-Log -Message "$($OEMInformationItem.Name) value is defined" -Component "$region"
                    Write-Log -Message "Configuring $($OEMInformationItem.Name) value to '$($OEMInformationItem.Value)'" -Component "$region"
                    Set-RegistryItem -Action Add -Root HKLM -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "$($OEMInformationItem.Name)" -PropertyType String -Value "$($OEMInformationItem.Value)"
                }
            }
            #endregion

            #region :: Windows registration
            foreach ($registrationItem in $config.windowsBranding.registrationItems.PsObject.Properties) {
                if ([string]::IsNullOrEmpty($registrationItem.Value)) {
                    Write-Log -Message "$($registrationItem.Name) value is not defined" -Component "$region" -Severity 2
                }
                else {
                    Write-Log -Message "$($registrationItem.Name) value is defined" -Component "$region"
                    Write-Log -Message "Configuring $($registrationItem.Name) value to '$($registrationItem.Value)'" -Component "$region"
                    Set-RegistryItem -Action Add -Root HKLM -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "$($registrationItem.Name)" -PropertyType String -Value "$($registrationItem.Value)"
                }
            }
            #endregion
        }
        else {
            Write-Log -Message "ERROR: Windows branding requires SYSTEM install behavior - this module writes to HKLM registry paths that are not accessible in USER context" -Component "$region" -Severity 3
            Write-Log -Message "Skipping Windows branding - current installBehavior is '$($config.metadata.installBehavior)'" -Component "$region" -Severity 2
            if ($exitOnError) {
                exit 1
            }
        }
        Write-Log -Message "Windows branding completed" -Component "$region"
    }
    else {
        Write-Log -Message "Windows branding is disabled" -Component "$region"
    }
    #endregion

    #region :: windowsConfig
    <#
    WindowsConfig — STATUS: In review / Under design

    Leverage Windows Package Manager (WinGet) Configuration to apply
    declarative settings and install applications on Windows devices.

    The idea is to integrate WinGet Configuration files (.dsc.yaml) as a native
    feature module, allowing administrators to define application installations and
    system settings through the same JSON-driven approach used by other gecko modules.

    Key areas being explored:
    - Validating WinGet installation and minimum version (v1.6.2631 or later)
    - Processing one or more WinGet Configuration files per configuration
    - Handling WinGet availability in SYSTEM vs. USER context
    - Error handling and logging for configuration apply operations
    - Compatibility with Constrained Language Mode environments

    Design considerations:
    - How to best handle WinGet availability during Windows Autopilot provisioning
    - Whether to support both local and cloud-hosted .dsc.yaml files
    - Interaction with existing windowsApps module (overlap in app management)
    #>
    #endregion

    #region :: windowsFeatures
    $region = "windowsFeatures"
    Write-Log -Message "WINDOWS FEATURES" -Component "$region"
    if ($config.windowsFeatures.enabled -eq $true) {
        Write-Log -Message "Windows Features is enabled" -Component "$region"

        # Import Dism module for managing Windows features and capabilities, handle errors if module is not available.
        Import-Module -Name Dism -ErrorAction SilentlyContinue -Verbose:$false

        # Validate install behavior
        if ($config.metadata.installBehavior -eq "SYSTEM") {

            #region :: windowsFeatures
            [array]$windowsFeatures = $config.windowsFeatures.features
            foreach ($windowsFeature in $windowsFeatures) {
                Write-Log -Message "Processing $($windowsFeature.DisplayName)" -Component "$region"
                if ($($windowsFeature.State) -eq "LeaveAsIs") {
                    Write-Log -Message "$($windowsFeature.DisplayName) configured to leave as-is, skipping" -Component "$region"
                    continue
                }
                try {
                    [string]$featureState = (Get-WindowsOptionalFeature -Online -FeatureName $windowsFeature.FeatureName -Verbose:$false -ErrorAction Stop).state
                }
                catch {
                    $errMsg = $_.Exception.Message
                    if ($errMsg -match 'is unknown') {
                        Write-Log -Message "Feature not available on this OS build [$($windowsFeature.FeatureName)] - verify feature name and OS build compatibility" -Component "$region" -Severity 2
                    }
                    else {
                        Write-Log -Message "ERROR: Failed to get feature state for $($windowsFeature.DisplayName): $errMsg" -Component "$region" -Severity 3
                        if ($exitOnError) {
                            exit 1
                        }
                    }
                    continue
                }
                if ($($windowsFeature.State) -eq $featureState) {
                    Write-Log -Message "$($windowsFeature.DisplayName) configured [$($windowsFeature.State)]" -Component "$region"
                }
                else {
                    Write-Log -Message "Configuring $($windowsFeature.DisplayName) [$($windowsFeature.State)]" -Component "$region"
                    try {
                        switch ($($windowsFeature.State)) {
                            "ENABLED" {
                                Write-Log -Message "Enabling $($windowsFeature.DisplayName)" -Component "$region"
                                $windowsFeatureResult = Enable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -All -NoRestart -Verbose:$false
                                if ($windowsFeatureResult.RestartNeeded) {
                                    $requireReboot = $true
                                }
                                Write-Log -Message "Completed enabling $($windowsFeature.DisplayName). Restart needed: $($windowsFeatureResult.RestartNeeded)" -Component "$region"
                            }
                            "DISABLED" {
                                Write-Log -Message "Disabling $($windowsFeature.DisplayName)" -Component "$region"
                                $windowsFeatureResult = Disable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -NoRestart -Verbose:$false
                                if ($windowsFeatureResult.RestartNeeded) {
                                    $requireReboot = $true
                                }
                                Write-Log -Message "Completed disabling $($windowsFeature.DisplayName). Restart needed: $($windowsFeatureResult.RestartNeeded)" -Component "$region"
                            }
                            Default {
                                Write-Log -Message "Unsupported state $($windowsFeature.DisplayName) [$($windowsFeature.State)]" -Component "$region"
                            }
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                        if ($exitOnError) {
                            exit 1
                        }
                    }
                }
            }
            #endregion

            #region :: windowsOptionalFeatures
            Write-Log -Message "WINDOWS OPTIONAL FEATURES" -Component "$region"
            [array]$windowsOptionalFeatures = $config.windowsFeatures.optionalFeatures
            foreach ($windowsOptionalFeature in $windowsOptionalFeatures) {
                Write-Log -Message "Processing $($windowsOptionalFeature.DisplayName)" -Component "$region"
                if ($($windowsOptionalFeature.State) -eq "LeaveAsIs") {
                    Write-Log -Message "$($windowsOptionalFeature.DisplayName) configured to leave as-is, skipping" -Component "$region"
                    continue
                }
                try {
                    [string]$featureState = (Get-WindowsCapability -Online -Name $windowsOptionalFeature.Name -Verbose:$false -ErrorAction Stop).state
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Write-Log -Message "ERROR: Failed to get capability state for $($windowsOptionalFeature.DisplayName): $errMsg" -Component "$region" -Severity 3
                    if ($exitOnError) {
                        exit 1
                    }
                    continue
                }
                if ($($windowsOptionalFeature.State) -eq $featureState) {
                    Write-Log -Message "$($windowsOptionalFeature.DisplayName) configured [$($windowsOptionalFeature.State)]" -Component "$region"
                }
                else {
                    Write-Log -Message "Configuring $($windowsOptionalFeature.DisplayName) [$($windowsOptionalFeature.State)]" -Component "$region"
                    switch ($($windowsOptionalFeature.State)) {
                        "INSTALLED" {
                            Write-Log -Message "Installing $($windowsOptionalFeature.DisplayName)" -Component "$region"
                            try {
                                $windowsCapabilityResult = Add-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false
                                if ($windowsCapabilityResult.RestartNeeded) {
                                    $requireReboot = $true
                                }
                                Write-Log -Message "Completed installing $($windowsOptionalFeature.DisplayName), restart needed: $($windowsCapabilityResult.RestartNeeded)" -Component "$region"
                            }
                            catch {
                                $errMsg = $_.Exception.Message
                                Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                                if ($exitOnError) {
                                    exit 1
                                }
                            }
                        }
                        "NOTPRESENT" {
                            Write-Log -Message "Removing $($windowsOptionalFeature.DisplayName)" -Component "$region"
                            try {
                                $windowsCapabilityResult = Remove-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false
                                if ($windowsCapabilityResult.RestartNeeded) {
                                    $requireReboot = $true
                                }
                                Write-Log -Message "Completed removing $($windowsOptionalFeature.DisplayName), restart needed: $($windowsCapabilityResult.RestartNeeded)" -Component "$region"
                            }
                            catch {
                                $errMsg = $_.Exception.Message
                                Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                                if ($exitOnError) {
                                    exit 1
                                }
                            }
                        }
                        Default {
                            Write-Log -Message "Unsupported state $($windowsOptionalFeature.DisplayName) [$($windowsOptionalFeature.State)]" -Component "$region"
                        }
                    }
                }
            }
            #endregion

            Write-Log -Message "Windows Features completed" -Component "$region"
        }
        else {
            Write-Log -Message "ERROR: Windows Features requires SYSTEM install behavior - enabling and disabling Windows features requires elevated SYSTEM context" -Component "$region" -Severity 3
            Write-Log -Message "Skipping Windows Features - current installBehavior is '$($config.metadata.installBehavior)'" -Component "$region" -Severity 2
            if ($exitOnError) {
                exit 1
            }
        }
    }
    else {
        Write-Log -Message "Windows Features is disabled" -Component "$region"
    }
    #endregion

    #region :: windowsFiles
    $region = "windowsFiles"
    Write-Log -Message "WINDOWS FILES" -Component "$region"
    if ($config.windowsFiles.enabled -eq $true) {
        Write-Log -Message "Windows Files is enabled" -Component "$region"
        [string]$assetFile = $config.windowsFiles.assetFile
        if ($assetFile.StartsWith("https://","CurrentCultureIgnoreCase")) {

            #region :: Download cloud asset file
            Write-Log -Message "Downloading asset file [$($assetFile)]" -Component "$region"
            $assetOutFile = "$($Env:TEMP)\$(Split-Path -Leaf $assetFile)"
            try {
                $webRequestResponse = Invoke-WebRequest -Uri $assetFile -OutFile $assetOutFile -PassThru -UseBasicParsing
                if ($webRequestResponse.StatusCode -eq 200) {
                    Write-Log -Message "$(Split-Path -Leaf $assetFile) downloaded successfully [$($assetOutFile)]" -Component "$region"
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                if ($exitOnError) {
                    exit 1
                }
            }
            #endregion

            #region :: Expand cloud asset file
            if (Test-Path -Path $assetOutFile -PathType Leaf) {
                Write-Log -Message "Windows Files found $($assetOutFile)" -Component "$region"
                Write-Log -Message "Windows Files is expanding $($assetOutFile)" -Component "$region"
                try {
                    Expand-Archive -Path "$assetOutFile" -DestinationPath "$($Env:TEMP)" -Force
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
            }
            else {
                Write-Log -Message "Asset file ($assetOutFile) not present" -Component "$region"
            }
            #endregion
        }
        else {
            #region :: Expand local asset file
            if (Test-Path -Path $assetFile -PathType Leaf) {
                Write-Log -Message "Windows Files found $assetFile" -Component "$region"
                Write-Log -Message "Windows Files is expanding $((Get-Item $assetFile).FullName)" -Component "$region"
                try {
                    Expand-Archive -Path "$assetFile" -DestinationPath "$($Env:TEMP)" -Force
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
            }
            else {
                Write-Log -Message "Asset file ($assetFile) not present" -Component "$region"
            }
            #endregion
        }
        [array]$windowsFileItems = $($config.windowsFiles.items)
        foreach ($windowsFileItem in $windowsFileItems) {
            Write-Log -Message "Processing $($windowsFileItem.name)" -Component "$region"
            Write-Log -Message "$($windowsFileItem.description)" -Component "$region"

            if (Test-OSBuildInRange -MinOSBuild $([int]$windowsFileItem.minOSbuild) -MaxOSBuild $([int]$windowsFileItem.maxOSbuild) -ItemDescription $($windowsFileItem.description) -Component $region) {

                #region :: Expanding Windows environment variables
                $expandedTargetFile = Expand-EnvironmentVariables -Path $($windowsFileItem.targetFile) -Component $region
                if ($null -eq $expandedTargetFile) {
                    Continue
                }
                $windowsFileItem.targetFile = $expandedTargetFile
                #endregion

                #region :: File copy process
                try {
                    if (Test-Path -Path "$($Env:TEMP)\$($windowsFileItem.sourceFile)" -PathType Leaf) {
                        Write-Log -Message "$($Env:TEMP)\$($windowsFileItem.sourceFile) exist. Preparing copying file to $($windowsFileItem.targetFile)" -Component "$region"
                        if (!(Test-Path -path $(Split-Path -Path $($windowsFileItem.targetFile) -Parent))) {
                            Write-Log -Message "Target folder not found, creating folder $(Split-Path -Path $($windowsFileItem.targetFile) -Parent)" -Component "$region"
                            New-Item $(Split-Path -Path $($windowsFileItem.targetFile) -Parent) -Type Directory -Force | Out-Null
                        }
                        Write-Log -Message "Copying file to $($windowsFileItem.targetFile)" -Component "$region"
                        Copy-Item -Path "$($Env:TEMP)\$($windowsFileItem.sourceFile)" -Destination "$($windowsFileItem.targetFile)" -Force
                    }
                    else {
                        Write-Log -Message "$($Env:TEMP)\$($windowsFileItem.sourceFile) not found. File copy canceled" -Component "$region"
                    }
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                #endregion
            }
        }
        Write-Log -Message "Windows Files completed" -Component "$region"
    }
    else {
        Write-Log -Message "Windows Files is disabled" -Component "$region"
    }
    #endregion

    #region :: windowsGroups
    <#
    WindowsGroups — STATUS: In review / Under design

    This module is intended to manage local group memberships on Windows devices.

    The original use case was narrow: adding specific accounts (e.g., INTERACTIVE) to
    local groups such as "Hyper-V Administrators" alongside enabling the Hyper-V feature.
    This remains a valid but limited scenario.

    A broader concept is being explored: a manifest-based approach where a manifest
    file describes the expected members of local groups (users and groups). The module
    would then validate the actual group membership against the manifest and remediate
    differences — detecting unauthorized additions (e.g., unexpected accounts in the
    local Administrators group) as well as ensuring required members are present.

    Design considerations:
    - Manifest file defining expected group memberships (desired state)
    - Detection of extra/unauthorized members added outside of default configuration
    - Add and remove operations to bring groups into the desired state
    - Reporting and logging of drift from the expected membership
    #>
    #endregion

    #region :: windowsRegistry
    $region = "windowsRegistry"
    Write-Log -Message "WINDOWS REGISTRY ITEMS" -Component "$region"
    if ($config.windowsRegistry.enabled -eq $true) {
        Write-Log -Message "Windows Registry items is enabled" -Component "$region"
        [array]$windowsRegistryItems = $config.windowsRegistry.items

        #region :: Loading Default User registry hive (NTuser.dat)
        if ($windowsRegistryItems.root -contains "HKDU") {
            Write-Log -Message "Default User Registry item(s) found" -Component "$region"
            $hiveLoaded = Mount-DefaultUserHive -Component $region
            if (-not $hiveLoaded -and $exitOnError) {
                exit 1
            }
        }
        else {
            Write-Log -Message "Loading Default User Registry hive not required" -Component "$region"
        }
        #endregion

        #region :: Processing Windows Registry Items
        foreach ($windowsRegistryItem in $windowsRegistryItems) {
            Write-Log -Message "Processing $($windowsRegistryItem.description)" -Component "$region"
            try {
                if (Test-OSBuildInRange -MinOSBuild $([int]$windowsRegistryItem.minOSbuild) -MaxOSBuild $([int]$windowsRegistryItem.maxOSbuild) -ItemDescription $($windowsRegistryItem.description) -Component $region) {
                    switch ($windowsRegistryItem.item) {
                        "ADD" {
                            Write-Log -Message "Adding $($windowsRegistryItem.root):\$($windowsRegistryItem.path) [$($windowsRegistryItem.Type)] $($windowsRegistryItem.name) ""$($windowsRegistryItem.Value)""" -Component "$region"
                            Set-RegistryItem -Action Add -Root "$($windowsRegistryItem.root)" -Path "$($windowsRegistryItem.path)" -Name "$($windowsRegistryItem.name)" -PropertyType "$($windowsRegistryItem.Type)" -Value "$($windowsRegistryItem.Value)"
                        }
                        "REMOVE" {
                            Write-Log -Message "Removing $($windowsRegistryItem.root):\$($windowsRegistryItem.path) ""$($windowsRegistryItem.name)"" setting from registry" -Component "$region"
                            Set-RegistryItem -Action Remove -Root "$($windowsRegistryItem.root)" -Path "$($windowsRegistryItem.path)" -Name "$($windowsRegistryItem.name)"
                        }
                        Default {
                            Write-Log -Message "Unsupported value for [$($windowsRegistryItem.description)] | [$($windowsRegistryItem.item)]" -Component "$region"
                        }
                    }
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                if ($exitOnError) {
                    exit 1
                }
            }
        }
        #endregion

        Write-Log -Message "Windows Registry items completed" -Component "$region"
    }
    else {
        Write-Log -Message "Windows Registry items is disabled" -Component "$region"
    }
    #endregion

    #region :: windowsRun
    $region = "windowsRun"
    Write-Log -Message "WINDOWS EXECUTABLES" -Component "$region"
    if ($config.windowsRun.enabled -eq $true) {
        Write-Log -Message "Windows Executables is enabled" -Component "$region"
        [array]$windowsRun = $config.windowsRun.items
        foreach ($windowsExecutable in $windowsRun) {
            Write-Log -Message "Processing $($windowsExecutable.name)" -Component "$region"
            Write-Log -Message "$($windowsExecutable.description)" -Component "$region"

            if (Test-OSBuildInRange -MinOSBuild $([int]$windowsExecutable.minOSbuild) -MaxOSBuild $([int]$windowsExecutable.maxOSbuild) -ItemDescription $($windowsExecutable.description) -Component $region) {

                #region :: Expanding Windows environment variables
                $expandedFilePath = Expand-EnvironmentVariables -Path $($windowsExecutable.filePath) -Component $region
                if ($null -eq $expandedFilePath) {
                    Continue
                }
                $windowsExecutable.filePath = $expandedFilePath
                #endregion

                #region :: Download item
                if ($($windowsExecutable.downloadUri)) {
                    Write-Log -Message "Download Uri $($windowsExecutable.downloadUri)" -Component "$region"
                    Write-Log -Message "Download target $($windowsExecutable.filePath)" -Component "$region"
                    try {
                        $webRequestResponse = Invoke-WebRequest -Uri $($windowsExecutable.downloadUri) -OutFile $($windowsExecutable.filePath) -PassThru -UseBasicParsing
                        if ($webRequestResponse.StatusCode -eq 200) {
                            Write-Log -Message "$((Get-Item $($windowsExecutable.filePath)).Name) downloaded successfully" -Component "$region"
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                        if ($exitOnError) {
                            exit 1
                        }
                    }
                }
                #endregion

                #region :: Executing item
                if (Test-Path $($windowsExecutable.filePath)) {
                    Write-Log -Message "File path $($windowsExecutable.filePath) exists" -Component "$region"
                    Write-Log -Message "File description $((Get-Item $($windowsExecutable.filePath)).VersionInfo.FileDescription)" -Component "$region"
                    Write-Log -Message "File version: $((Get-Item $($windowsExecutable.filePath)).VersionInfo.FileVersion)" -Component "$region"
                    try {
                        if ($($windowsExecutable.ArgumentList)) {
                            Write-Log -Message "Executing $($windowsExecutable.filePath) with arguments $($windowsExecutable.ArgumentList)" -Component "$region"
                            Start-Process -FilePath $($windowsExecutable.filePath) -ArgumentList $($windowsExecutable.ArgumentList) -NoNewWindow -Wait

                        }
                        else {
                            Write-Log -Message "Executing $($windowsExecutable.filePath) with no arguments" -Component "$region"
                            Start-Process -FilePath $($windowsExecutable.filePath) -NoNewWindow -Wait
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                        if ($exitOnError) {
                            exit 1
                        }
                    }
                }
                else {
                    Write-Log -Message "File not found [$($windowsExecutable.filePath)]" -Component "$region"
                }
                #endregion
            }
        }
        Write-Log -Message "Windows Executables completed" -Component "$region"
    }
    else {
        Write-Log -Message "Windows Executables is disabled" -Component "$region"
    }
    #endregion

    #region :: windowsServices
    $region = "windowsServices"
    Write-Log -Message "WINDOWS SERVICES" -Component "$region"
    if ($config.windowsServices.enabled -eq $true) {
        Write-Log -Message "Windows Services is enabled" -Component "$region"

        # Validate install behavior
        if ($config.metadata.installBehavior -eq "SYSTEM") {

            # Building array of services to process from configuration file
            [array]$windowsServices = $config.windowsServices.services

            # Iterating through services and configuring startup type and service state based on configuration file values
            foreach ($windowsService in $windowsServices) {
                Write-Log -Message "Processing $($windowsService.DisplayName) [$($windowsService.Name)]" -Component "$region"
                if ($($windowsService.StartType) -eq "LeaveAsIs") {
                    Write-Log -Message "$($windowsService.DisplayName) configured to leave as-is, skipping" -Component "$region"
                    continue
                }
                try {
                    [array]$windowsServiceStatus = Get-Service -Name $windowsService.Name -ErrorAction SilentlyContinue
                    if ($windowsServiceStatus) {
                        Write-Log -Message "$($windowsServiceStatus.DisplayName) found! | Status: $($windowsServiceStatus.Status) | StartType: $($windowsServiceStatus.StartType)" -Component "$region"
                        if ($windowsService.StartType -eq $windowsServiceStatus.StartType) {
                            Write-Log -Message "$($windowsService.Name) already configured" -Component "$region"
                        }
                        else {
                            Write-Log -Message "Reconfiguring $($windowsService.Name) [($($windowsServiceStatus.StartType) ->  $($windowsService.StartType))]" -Component "$region"
                            Set-Service -Name "$($windowsService.Name)" -StartupType "$($windowsService.StartType)"
                        }
                        if ($($windowsService.StopIfRunning) -eq $true -and $($windowsServiceStatus.Status) -eq "Running") {
                            Write-Log -Message "Stopping $($windowsService.DisplayName) [$($windowsService.Name)]" -Component "$region"
                            Stop-Service -Name "$($windowsService.Name)" -Force
                        }
                    }
                    else {
                        Write-Log -Message "$($windowsService.DisplayName) not found!" -Component "$region"
                    }
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
            }
            Write-Log -Message "Windows Services completed" -Component "$region"
        }
        else {
            Write-Log -Message "ERROR: Windows Services requires SYSTEM install behavior - configuring Windows services requires elevated SYSTEM context" -Component "$region" -Severity 3
            Write-Log -Message "Skipping Windows Services - current installBehavior is '$($config.metadata.installBehavior)'" -Component "$region" -Severity 2
            if ($exitOnError) {
                exit 1
            }
        }
    }
    else {
        Write-Log -Message "Windows Services is disabled" -Component "$region"
    }
    #endregion

    #region :: windowsScheduledTasks
    <#
    WindowsScheduledTasks — STATUS: In review / Under design

    Provides desired state configuration for Windows Scheduled Tasks, allowing
    administrators to declaratively define whether specific tasks should be enabled
    or disabled. This is useful for controlling system maintenance, telemetry,
    diagnostics, and other background operations across managed devices.

    Each task entry in the configuration specifies a task name, display name, and
    desired state (Enabled or Disabled). The module compares the current state of
    each task against the desired state and only applies changes when they differ,
    ensuring non-destructive, idempotent operations.

    Running tasks are automatically stopped before being disabled to prevent
    conflicts. Tasks that do not exist on the device are logged and skipped.

    Design considerations:
    - Task path support for disambiguating tasks with identical names
    - Interaction with Group Policy-managed scheduled tasks
    - Whether to support task creation or only state management of existing tasks
    #>
    #endregion

    #region :: windowsTCR
    <#
    WindowsTCR — STATUS: In preview
    This is a PREVIEW feature and may be subject to changes in functionality.
    #>
    $region = "windowsTCR"
    Write-Log -Message "WINDOWS TIME ZONE, CULTURE, AND REGIONAL SETTINGS MANAGER" -Component "$region"
    if ($config.windowsTCR.enabled -eq $true) {
        Write-Log -Message "Windows Time zone, culture, and regional settings manager is enabled" -Component "$region"

        # Writing current Time zone, culture, and regional settings to log
        Write-Log -Message "Current Time zone: $((Get-TimeZone).Id)" -Component "$region"
        Write-Log -Message "Current Culture: $((Get-Culture).Name)" -Component "$region"
        Write-Log -Message "Current Home Location GeoID: $((Get-WinHomeLocation).GeoId)" -Component "$region"

        # Writing Windows Time zone, culture, and regional settings configurations to log
        Write-Log -Message "Reading Windows Time zone, culture, and regional settings from configuration file" -Component "$region"
        [array]$windowsTCRconfigurations = $config.windowsTCR.configurations

        # Determining CID value and configuring Windows Time zone, culture, and regional settings
        if ($windowsTCRconfigurations.Count -ge 1) {
            Write-Log -Message "Found $($windowsTCRconfigurations.Count) Windows Time zone, culture, and regional settings configurations" -Component "$region"
            if ($CultureIdentifier) {
                Write-Log -Message "Windows Time zone, culture, and regional settings CID value defined ($CultureIdentifier)" -Component "$region"
                $CIDvalue = $CultureIdentifier
            }
            else  {
                Write-Log -Message "Windows Time zone, culture, and regional settings CID value not defined, looking up default value" -Component "$region"
                if ([string]::IsNullOrEmpty($config.windowsTCR.settings.defaultCID)) {
                    Write-Log -Message "Windows Time zone, culture, and regional settings default value not defined" -Component "$region"
                }
                else {
                    Write-Log -Message "Windows Time zone, culture, and regional settings default value found, setting CID value to '$($config.windowsTCR.settings.defaultCID)'" -Component "$region"
                    $CIDvalue = ($config.windowsTCR.settings.defaultCID)
                }
            }

            #region :: Determine CID settings based on Computer name comparison
            if ($config.windowsTCR.computerNameComparison.enabled) {
                Write-Log -Message "Computer name comparison enabled" -Component "$region"
                Write-Log -Message "Computer name '$env:COMPUTERNAME'" -Component "$region"
                [bool]$CIDfound = $false
                foreach ($CIDitem in $config.windowsTCR.configurations.CID) {
                    Write-Log -Message "Checking if computer name $($config.windowsTCR.computerNameComparison.operator) '$CIDitem'" -Component "$region"
                    # CLM-compatible: use -like operator instead of .NET string methods
                    $comparisonResult = switch ($config.windowsTCR.computerNameComparison.operator) {
                        'StartsWith' { $env:COMPUTERNAME -like "$CIDitem*" }
                        'EndsWith'   { $env:COMPUTERNAME -like "*$CIDitem" }
                        'Contains'   { $env:COMPUTERNAME -like "*$CIDitem*" }
                        'Equals'     { $env:COMPUTERNAME -eq $CIDitem }
                        default      { $false }
                    }
                    if ($comparisonResult) {
                        Write-Log -Message "$env:COMPUTERNAME $($config.windowsTCR.computerNameComparison.operator) '$CIDitem'" -Component "$region"
                        Write-Log -Message "Configuring CID value to '$CIDitem'" -Component "$region"
                        $CIDfound = $true
                        break
                    }
                }
                if ($CIDfound) {
                    Write-Log -Message "Overwriting CID value with value from computer name comparison" -Component "$region"
                    $CIDvalue = $CIDitem
                }
                else {
                    Write-Log -Message "Computer name comparison did not find a match" -Component "$region" -Severity 2
                }
            }
            else {
                Write-Log -Message "Computer name comparison disabled" -Component "$region"
            }
            #endregion

            #region :: Determine CID settings based on local file

            <#
            Solution deprecated - to be reviewed/removed in future release

            Settings a CID value based on the presence of a file on the local file system. The file path is defined in the configuration file.
            If the file is present, the CID value is set to the value defined in the configuration file. If the file is not present, no action is taken.

            File to be created in <system-root>\Recovery\OEM\<filename>.json by gecko windowsTCR GUI.

            Design considerations:
            - How to handle standard user permissions and potential access issues to the file path (e.g., C:\Recovery\OEM may have restricted permissions).
            - Whether to use file presence as a binary marker or to read content from the file for more granular configuration (e.g., JSON content with specific CID value).
            - Schedules task approach for re-evaluating the file presence and updating CID value accordingly, especially if the file may be added or removed after initial configuration.
            - Security implications of using file presence for configuration, including potential for unauthorized changes and how to mitigate (e.g., monitoring file integrity, using secure file permissions).
            #>

            #endregion

            #region :: Determine CID settings based on Location marker value in registry
            if ($config.windowsTCR.locationMarker.enabled) {
                Write-Log -Message "Location marker usage is enabled" -Component "$region"

                # Read registry path configuration from locationMarker
                $locationMarkerRoot = $config.windowsTCR.locationMarker.root
                $locationMarkerPath = $config.windowsTCR.locationMarker.path
                $locationMarkerName = $config.windowsTCR.locationMarker.name

                # Build full registry path
                $registryPath = "$($locationMarkerRoot):\$locationMarkerPath"
                Write-Log -Message "Registry path: $registryPath" -Component "$region"
                Write-Log -Message "Registry value name: $locationMarkerName" -Component "$region"

                # Check if registry path and value exist
                if (Test-Path -Path $registryPath) {
                    try {
                        $locationMarkerValue = (Get-ItemProperty -Path $registryPath -Name $locationMarkerName -ErrorAction Stop).$locationMarkerName
                        if (-not [string]::IsNullOrEmpty($locationMarkerValue)) {
                            Write-Log -Message "Location marker value found: '$locationMarkerValue'" -Component "$region"
                            # Validate that the location marker value matches a configured CID
                            if ($windowsTCRconfigurations.CID -contains $locationMarkerValue) {
                                Write-Log -Message "Overwriting CID value with value from location marker" -Component "$region"
                                $CIDvalue = $locationMarkerValue
                            }
                            else {
                                Write-Log -Message "Location marker value '$locationMarkerValue' does not match any configured CID" -Component "$region" -Severity 2
                            }
                        }
                        else {
                            Write-Log -Message "Location marker value is empty, no action taken" -Component "$region"
                        }
                    }
                    catch {
                        Write-Log -Message "Location marker registry value '$locationMarkerName' not found, no action taken" -Component "$region"
                    }
                }
                else {
                    Write-Log -Message "Location marker registry path not found, no action taken" -Component "$region"
                }
            }
            else {
                Write-Log -Message "Location marker usage is disabled" -Component "$region"
            }
            #endregion

            #region :: Configure WindowsTCR configurations
            if ($windowsTCRconfigurations.CID -contains $CIDvalue) {
                Write-Log -Message "Valid Windows Time zone, culture, and regional settings CID value, querying '$CIDvalue'" -Component "$region"
                $windowsTCRSettings = $($config.windowsTCR.configurations) | Where-Object {$_.CID -eq $CIDvalue}
                Write-Log -Message "Configuring Windows Time zone, culture, and regional settings" -Component "$region"
                if ([string]::IsNullOrEmpty($windowsTCRSettings.description)) {
                    Write-Log -Message "-- no description --" -Component "$region"
                }
                else {
                    Write-Log -Message "$($windowsTCRSettings.description)" -Component "$region"
                }
                #region :: Configure Time zone, Culture, Home Location, and related settings
                try {
                    # Configure Time zone, Culture, Home Location
                    Write-Log -Message "Setting Time zone: $((Get-TimeZone).Id) -> $($windowsTCRSettings.timezone)" -Component "$region"
                    Set-TimeZone -Name $($windowsTCRSettings.timezone)
                    Write-Log -Message "Setting Culture: $((Get-Culture).Name) -> $($windowsTCRSettings.culture)" -Component "$region"
                    Set-Culture -CultureInfo $($windowsTCRSettings.culture)
                    Write-Log -Message "Setting Home Location GeoID: $((Get-WinHomeLocation).GeoId) -> $($windowsTCRSettings.homeLocation)" -Component "$region"
                    Set-WinHomeLocation -GeoId $($windowsTCRSettings.homeLocation)

                    Write-Log -Message "Configured Time zone: $((Get-TimeZone).Id)" -Component "$region"
                    Write-Log -Message "Configured Culture: $((Get-ItemProperty -Path "HKCU:\Control Panel\International" -Name "LocaleName").LocaleName)" -Component "$region"
                    Write-Log -Message "Configured Home Location GeoID: $((Get-WinHomeLocation).GeoId)" -Component "$region"
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                    if ($exitOnError) {
                        exit 1
                    }
                }
                #endregion

                #region :: Copy user international settings to system
                if ($config.windowsTCR.settings.copyUserInternationalSettingsToSystem) {
                    Write-Log -Message "Copying user international settings to system is enabled" -Component "$region"
                    try {
                        if ($script:CurrentOSBuild -ge 22000) {
                            Write-Log -Message "Copying user international settings to Welcome Screen and New Users" -Component "$region"
                            Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true
                        }
                        else {
                            Write-Log -Message "Copying user international settings to system is not supported on this Windows build" -Component "$region" -Severity 2
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                        if ($exitOnError) {
                            exit 1
                        }
                    }
                }
                else {
                    Write-Log -Message "Copying user international settings to system is disabled" -Component "$region"
                }

                #endregion
            }
            else {
                Write-Log -Message "Windows Time zone, culture, and regional settings CID value unknown or empty" -Component "$region" -Severity 2
                Write-Log -Message "Windows Time zone, culture, and regional settings not re-configured" -Component "$region"
            }
            #endregion
        }
        else {
            Write-Log -Message "Windows Time zone, culture, and regional settings configurations not defined in configuration file" -Component "$region" -Severity 2
            Write-Log -Message "Windows Time zone, culture, and regional settings not re-configured" -Component "$region"
        }

        #region :: Configure Windows NTP server
        if ($config.windowsTCR.ntpServer.enabled -eq $true) {
            Write-Log -Message "Configuring NTP Server is enabled" -Component "$region"
            try {
                if ($config.windowsTCR.ntpServer.peerList.Count -ge 1) {
                    Write-Log -Message "NTP Server peer list contains $($config.windowsTCR.ntpServer.peerList.Count) peer(s)" -Component "$region"
                    [string]$NTPServerList = $config.windowsTCR.ntpServer.peerList -join ' '
                    Write-Log -Message "NTP Server peer list: $NTPServerList" -Component "$region"
                    Write-Log -Message "Configuring NTP Server settings" -Component "$region"
                    if ($((Get-Service -Name w32time -ErrorAction SilentlyContinue).Status) -eq "Running") {
                        Write-Log -Message "Windows Time service is started" -Component "$region"
                    }
                    else {
                        Write-Log -Message "Windows Time service is stopped, attempting to start the service" -Component "$region"
                        Start-Service -Name w32time
                    }
                    Start-Process -FilePath "$($env:Windir)\System32\w32tm.exe" -ArgumentList "/config /update /manualpeerlist:""$($NTPServerList -replace '^\s+|\s+$')"" /syncfromflags:MANUAL" -NoNewWindow -Wait
                }
                else {
                    Write-Log -Message "NTP Server peer list is empty" -Component "$region"
                }
                Write-Log -Message "Restarting Windows Time service" -Component "$region"
                Restart-Service -Name w32time -Force
            }
            catch {
                $errMsg = $_.Exception.Message
                Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                if ($exitOnError) {
                    exit 1
                }
            }
            Write-Log -Message "Configuring NTP Server is completed" -Component "$region"
        }
        else {
            Write-Log -Message "Configuring NTP Server is disabled" -Component "$region"
        }
        #endregion
        Write-Log -Message "Windows Time zone, culture, and regional settings manager completed" -Component "$region"
    }
    else {
        Write-Log -Message "Windows Time zone, culture, and regional settings manager is disabled" -Component "$region"
    }
    #endregion

    #region :: metadata
    $region = "metadata"
    Write-Log -Message "METADATA ITEMS" -Component "$region"
    if ($config.metadata.enabled -eq $true) {
        Write-Log -Message "Metadata items is enabled" -Component "$region"
        # Validating registry root based on installBehavior value
        switch ($config.metadata.installBehavior) {
            "SYSTEM" {
                $metadataRoot = "HKLM"
            }
            "USER" {
                $metadataRoot = "HKCU"
            }
            Default {
                Write-Log -Message "ERROR: Processing metadata items failed - invalid installBehavior '$($config.metadata.installBehavior)'" -Component "$region" -Severity 3
                $metadataRoot = $null
                if ($exitOnError) {
                    exit 1
                }
            }
        }

        # Validating that GUID value is present and not empty
        if ([string]::IsNullOrEmpty($config.metadata.guid)) {
            Write-Log -Message "ERROR: Processing metadata items failed - GUID is missing or empty" -Component "$region" -Severity 3
            $metadataRoot = $null
            if ($exitOnError) {
                exit 1
            }
        }

        #region :: metadata entries
        if ([string]::IsNullOrEmpty($metadataRoot)) {
            Write-Log -Message "Skipping metadata registry entries - no valid root defined" -Component "$region" -Severity 2
        }
        else {
            try {
                Set-RegistryItem -Action Add -Root $metadataRoot -Path "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -Name "Comments" -PropertyType String -Value "$($config.metadata.Comments)" -Force
                Set-RegistryItem -Action Add -Root $metadataRoot -Path "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -Name "DisplayName" -PropertyType String -Value "$($config.metadata.title)" -Force
                Set-RegistryItem -Action Add -Root $metadataRoot -Path "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -Name "DisplayVersion" -PropertyType String -Value "$($config.metadata.version)" -Force
                Set-RegistryItem -Action Add -Root $metadataRoot -Path "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -Name "InstallBehavior" -PropertyType String -Value "$($config.metadata.installBehavior)" -Force
                Set-RegistryItem -Action Add -Root $metadataRoot -Path "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -Name "InstallDate" -PropertyType String -Value "$(Get-Date -Format "yyyyMMdd")" -Force
                Set-RegistryItem -Action Add -Root $metadataRoot -Path "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -Name "Publisher" -PropertyType String -Value "$($config.metadata.publisher)" -Force
                Set-RegistryItem -Action Add -Root $metadataRoot -Path "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -Name "SystemComponent" -PropertyType DWord -Value 1 -Force
                Set-RegistryItem -Action Add -Root $metadataRoot -Path "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -Name "Version" -PropertyType String -Value "$($config.metadata.version)" -Force
            }
            catch {
                $errMsg = $_.Exception.Message
                Write-Log -Message "ERROR: $errMsg" -Component "$region" -Severity 3
                if ($exitOnError) {
                    exit 1
                }
            }
        }
        #endregion

        Write-Log -Message "Metadata items completed" -Component "$region"
    }
    else {
        Write-Log -Message "Metadata items is disabled" -Component "$region"
    }
    #endregion
}
end {
    #region :: resetting run Preference
    $region = "resetting"
    $global:ProgressPreference = $envProgressPreference
    $WarningPreference = $envWarningPreference
    #endregion

    #region :: reboot
    $region = "reboot"
    Write-Log -Message "Require reboot: $requireReboot" -Component "$region"
    #endregion

    #region :: cleaning-up
    $region = "clean-up"
    Write-Log -Message "Finishing up..." -Component "$region"

    # Unload Default User registry hive if still mounted
    Dismount-DefaultUserHive -Component $region

    Write-Log -Message "Cleaning up environment" -Component "$region"
    Write-Log -Message "## $($config.metadata.title) completed" -Component "$region"
    #endregion

    # Exit with success code for deployment tooling
    exit 0
}
#

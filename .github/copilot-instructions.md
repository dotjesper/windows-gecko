# Copilot Instructions — Windows gecko

## Project Overview

Windows gecko is a **desired state configuration** tool (not policy enforcement) for Windows 10/11 devices, primarily targeting Windows Autopilot and Microsoft Intune deployments. A single PowerShell script (`solution/gecko.ps1`) reads a JSON configuration file and applies modular settings — apps, features, registry, services, files, executables, branding, and regional settings (TCR).

## Architecture

- **Single-script engine**: `solution/gecko.ps1` — structured as `begin` (parse config, define functions), `process` (execute feature modules sequentially), `end` (cleanup, dismount hives).
- **JSON-driven configuration**: All behavior is defined in JSON config files validated against `solution/gecko-config.schema.json`. The script itself should never need modification for different deployments.
- **Feature modules** are `#region` blocks in the `process` block, each gated by `$config.<module>.enabled`. Execution order: windowsApps → windowsBranding → windowsFeatures → windowsFiles → windowsRegistry → windowsRun → windowsServices → windowsTCR → metadata.

## Critical Constraints

### PowerShell Constrained Language Mode (CLM)
All code **must** work under CLM (AppLocker/WDAC environments). This means:
- No `[Convert]`, `[System.IO.Path]`, or other .NET type accelerators (except `[int]`, `[string]`, `[bool]`, `[array]`, `[version]`, `[IntPtr]`)
- No `.GetEnumerator()`, `.Trim()` methods on strings — use PowerShell operators instead (e.g., `-replace '^\\+|\\+$'`)
- No `$PSCmdlet.ShouldProcess()` — use `$script:IsConstrainedLanguageMode` guard
- Binary registry values (`REG_BINARY`) are the sole exception — logged as warning and skipped under CLM
- Use `switch` statements instead of dynamic method invocation (e.g., `$env:COMPUTERNAME.StartsWith()` via switch)

### PowerShell 5.1 Compatibility
Target runtime is PowerShell 5.1 (`#requires -version 5.1`). Do not use PowerShell 7+ syntax (ternary `?:`, null-coalescing `??`, pipeline chain `&&`).

## Coding Conventions

- **Logging**: Use `Write-Log` for all runtime messages — never `Write-Host` or `Write-Output` (except fatal config errors in `begin`). Log format is CMTrace/IME-compatible.
- **Region structure**: Each feature module is wrapped in `#region :: moduleName` / `#endregion` using camelCase matching the JSON config key (e.g., `#region :: windowsRegistry`). The `$region` variable follows the same convention: `$region = "windowsRegistry"`. Preserve this structure.
- **Error handling pattern**: Every operation uses `try/catch/finally` with `$errMsg = $_.Exception.Message`, logs via `Write-Log -Severity 3`, and conditionally exits via `if ($exitOnError) { exit 1 }`.
- **Registry via `Set-RegistryItem`**: Supports roots `HKLM`, `HKCU`, `HKDU` (Default User hive), `HKCR`, `HKU`. Property types accept both PowerShell (`DWord`) and Win32 (`REG_DWORD`) names.
- **Default User hive**: Use `Mount-DefaultUserHive`/`Dismount-DefaultUserHive`. Tracked via `$script:defaultUserHiveLoaded`. Dismount always runs in `end` block cleanup.
- **OS build gating**: Items with `minOSbuild`/`maxOSbuild` use 5-digit Windows build numbers (e.g., `19045`, `22000`, `26100`). Empty string means no restriction.
- **Brace style**: Use Allman style for multi-line blocks — `}` and `else {` on separate lines. Inline single-expression patterns (e.g., `} else { $Value }`) are acceptable.
- **Early-out pattern**: In `foreach` loops, check for no-op or skip conditions (e.g., `"LeaveAsIs"` state, unsupported OS build) **before** making expensive API calls. Use `continue` to skip to the next iteration early. This avoids unnecessary cmdlet invocations (e.g., `Get-WindowsOptionalFeature`, `Get-WindowsCapability`) that are slow or may fail in restricted environments.
  ```powershell
  foreach ($item in $items) {
      if ($item.State -eq "LeaveAsIs") {
          Write-Log -Message "$($item.DisplayName) configured to leave as-is, skipping" -Component "$region"
          continue
      }
      # Expensive API call only runs when action is needed
      $currentState = Get-WindowsOptionalFeature -Online -FeatureName $item.FeatureName
      # ... process item
  }
  ```
- **Indentation**: 4 spaces for `.ps1`, 2 spaces for `.json` and `.xml` (see `.editorconfig`). Line endings: LF. Charset: UTF-8.

## JSON Configuration Structure

Config files reference `$schema: "./gecko-config.schema.json"`. Key sections:
- `metadata` — required: `enabled`, `installBehavior` (`SYSTEM`|`USER`), `guid`, `title`, `version`
- `runConditions` — `runScriptIn64bitPowerShell`, `requireReboot`
- Feature modules: `windowsApps`, `windowsBranding`, `windowsFeatures`, `windowsFiles`, `windowsRegistry`, `windowsRun`, `windowsServices`, `windowsTCR`

Sample configs in `samples/` follow naming convention: `baseline<Purpose><Context>.json` where `C` = computer/SYSTEM, `U` = user.

## Validation & Testing

- Run `Invoke-ScriptAnalyzer -Path .\gecko.ps1` (PSScriptAnalyzer) before submitting changes
- Test with both SYSTEM and USER context configurations — never mix contexts in one config
- Use `-Verbose` for interactive debugging; use `-WhatIf` where `SupportsShouldProcess` is declared
- Default log location: `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\`

## Adding a New Feature Module

1. Add JSON schema definition to `solution/gecko-config.schema.json` under `properties`
2. Add `#region :: newModule` block in the `process` section of `gecko.ps1`, following the enable-gate pattern:
   ```powershell
   #region :: newModule
   $region = "newModule"
   Write-Log -Message "NEW MODULE" -Component "$region"
   if ($($config.newModule.enabled) -eq $true) {
       # implementation
   }
   else {
       Write-Log -Message "New Module is disabled" -Component "$region"
   }
   #endregion
   ```
3. Add a sample config in `samples/` (e.g., `baselineNewModuleC.json`)
4. Ensure CLM compatibility — test with `$ExecutionContext.SessionState.LanguageMode` set to `ConstrainedLanguage`

## Documentation & Links

- **Product names**: Always use **Visual Studio Code** — not "VS Code".
- **Microsoft Learn URLs**: Never include the `/en-us/` locale segment. Use `https://learn.microsoft.com/mem/...` not `https://learn.microsoft.com/en-us/mem/...`. Microsoft Learn automatically redirects to the user's locale.
- **Legacy domains**: Use `learn.microsoft.com` instead of the deprecated `docs.microsoft.com`.

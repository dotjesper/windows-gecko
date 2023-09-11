---
Title: README
Date: March 28, 2023
Author: dotjesper
Status: In development
---

# Windows **gecko**

[![Built for Windows 11](https://img.shields.io/badge/Built%20for%20Windows%2011-Yes-blue?style=flat)](https://windows.com/ "Built for Windows 11")
[![Built for Windows 10](https://img.shields.io/badge/Built%20for%20Windows%2010-Yes-blue?style=flat)](https://windows.com/ "Built for Windows 10")
[![Built for Windows Autopilot](https://img.shields.io/badge/Built%20for%20Windows%20Autopilot-Yes-blue?style=flat)](https://docs.microsoft.com/en-us/mem/autopilot/windows-autopilot/ "Windows Autopilot")

[![PSScriptAnalyzer verified](https://img.shields.io/badge/PowerShell%20Script%20Analyzer%20verified-Yes-green?style=flat)](https://docs.microsoft.com/en-us/powershell/module/psscriptanalyzer/ "PowerShell Script Analyzer")
[![PowerShell Constrained Language mode verified](https://img.shields.io/badge/PowerShell%20Constrained%20Language%20mode%20verified-Yes-green?style=flat)](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes/ "PowerShell Language mode")

This repository contains the source code for **Windows gecko**.

<img src="./solution/gecko.png" width="200" title="Windows gecko logo" >

This repository is the evolution of the Windows rhythm functional script. During the progression of the solution I introduced braking changes, and to keep evolving the functionality, I decided to rebrand the solution, now **Windows gecko**.

According to Wikipedia, geckos are small, mostly carnivorous lizards that have a wide distribution, found on every continent except Antarctica. Geckoes are small in size, can adapt to the surroundings and communicating using clicking sounds in their social interactions.

> Geckos are small, adapts to the surroundings and have excellent night vision.

**Windows gecko** is exactly that, a multifunctional script, small in size, designed to adapt to multiple Windows management environments and using “clicking sounds” to ensure every steps is checked and recorded.


This repository is under development and alive and for the most, kicking - I welcome any feedback or suggestions for improvement. Reach out on [Twitter](https://twitter.com/dotjesper "dotjesper"), I read Direct Messages (DMs) and allow them from people I do not follow. For other means of contact, please visit [https://dotjesper.com/contact/](https://dotjesper.com/contact/ "Contact")

Do not hesitate to reach out if issues arise or new functionality and improvement comes to mind.

This is a personal development, please respect the community sharing philosophy and be nice!

Feel free to fork and build.

## Goal

The goal of **Windows gecko** is to provide a consistent desired state configuration to end user devices in [Windows Autopilot](https://learn.microsoft.com/en-us/mem/autopilot/windows-autopilot "Overview of Windows Autopilot") scenarios.

Windows gecko can easily be implemented using more traditionally deployment methods, e.g., Operating System Deployment (OSD), Task Sequences deployment or similar methods utilized.

## Synopsis

**Windows gecko** was built to remove a few Windows features from Windows devices, managed using Microsoft Endpoint Manager and evolved into a tool to align Windows feature configuration, allowing to disable and enable Windows features. While building the key features, additional requirements surfaced, and being able to baseline Windows In-box App was added, allowing administrators to easily remove unwanted apps as part of the initially configuration, e.g., when enforcing corporate defaults as part of Windows Autopilot scenarios.

Further improvements were added, baseline conditions were requested, and Windows Service configuration and Windows Registry configuration options has been included.

There as several ways to achieve a Windows desired state configuration baseline and several approaches. **Windows gecko** is built upon the requirement to provide a default configuration baseline, or a **desired state configuration**, and is not meant to stop the end user to install a previously removed app, or circumvent a desired setting, purely to allow device administrators to provide a default baseline, or corporate baseline, to the end user as part of a [Windows Autopilot](https://learn.microsoft.com/en-us/mem/autopilot/windows-autopilot "Overview of Windows Autopilot") scenario.

The mindset of the solution will aim to allow to limit and/or combine the functionalities best suited for the task, meaning if Windows feature configuration were to be applied, this should be achievable without the Windows Registry configuration. Also, very important, is to be able to apply Windows baselines configuration in one or multiple packages in either system or user context, without changing the code – which is why all configurations is achievable using configuration files (json). This will help ensure minimal effort to create a new Windows desired state configuration, being easily completed without any code changes or re-signing the provided code.

## Current features

- WindowsApps: Remove Windows In-box Apps and Store Apps.
- WindowsFeatures
    - Enable and/or disable Windows features.
    - Enable and/or disable Windows optional features.
- WindowsGroups: Add accounts to local groups (Coming soon).
- WindowsFiles: Copy file(s) to device from payload package.
- WindowsRegistry: Modifying Windows registry entries (add, change and remove).
- WindowsRun: Run local executables and/or download and run executables.
- WindowsServices: Configure/re-configure Windows Services.
- WindowsTCR: Windows Time zone, Culture and Regional settings manager (Preview).

## Requirements

**Windows gecko** is developed and tested for Windows 10 21H2 Pro and Enterprise 64-bit and newer and require PowerShell 5.1.

**NOTE** Applying Windows desired state configuration, **Windows gecko** should be configured to run in either SYSTEM or USER context. Applying device Baseline in SYSTEM context, will be required to run with local administrative rights (Local administrator or System). Combining device Baseline across SYSTEM and USER is highly unadvisable and might cause undesired results.

## Repository content

```
├── assets
│  ├─ LayoutModification-W10.xml
│  ├─ LayoutModification-W11.xml
│  ├─ windowsTCR.json
├── samples
│  ├─ baselineAppsC.json
│  ├─ baselineFeaturesC.json
│  ├─ baselineFileCopy.json
│  ├─ baselineFileExcute.json
│  ├─ baselineFileExplorerSettingsU.json
│  ├─ baselineFileOpenBehaviorC.json
│  ├─ baselineOfficeSettingsC.json
│  ├─ baselineOfficeSettingsU.json
│  ├─ baselineOptional_RSAT_FeaturesC.json
│  ├─ baselineServicesC.json
│  ├─ baselineSettingsC.json
│  ├─ baselineSettingsU.json
│  ├─ baselineWindowsTCR.json
├─ solution
│  ├─ assets.zip
│  ├─ configC.json
│  ├─ configU.json
│  ├─ gecko.png
│  ├─ gecko.ps1
```

## Usage

**Windows gecko** require a configuration file to work. The configuration file should be a valid json file, and the encoding should be UTF-8. The benefit using external configuration files, makes the solution more versatile and you can code sign the script once, and reuse the script for multiply deployment/tasks.

> I highly recommend code signing any script used in a deployment scenario. If you are unable to sign the script yourself, feel free to download a signed version from the [releases](https://github.com/dotjesper/windows-gecko/releases/).

### Parameters

***-configFile***

*Type: String*

Start Windows gecko with the defined configuration file to be used for the task. If no configuration file is defined, the script will look for .\config.json. If the configuration is not found or invalid, the script will exit.

***-CID***

*Type: string*

Windows Time zone, culture and regional settings value, allowing configuring culture, homelocation, and timezone from configuration file.

CID Value must match windowsTCR.configuration.[CID], e.g. "da-DK", "565652" or similar. See sample files for examples.

***-logFile***

*Type: String*

Start Windows gecko logging to the desired logfile. If no log file is defined, the script will default to **Windows gecko** log file within %ProgramData%\Microsoft\IntuneManagementExtension\Logs\ folder.

***-exitOnError***

*Type: Switch*

If an error occurs, *exitOnError* control if the script should exit-on-error. Default value is $false.

***-uninstall***

*Type: Switch*

Future parameter for use in Micrsoft Intune package deployment scenarios. Default value is $false.

***-Verbose***

Displays detailed information about the operation performed by Windows gecko. Without the -Verbose parameter, the script will run completely silent and will write output to the log file only.

### Examples

```powershell
.\gecko.ps1 -Verbose

.\gecko.ps1 -configFile ".\configC.json" -Verbose

.\gecko.ps1 -configFile ".\configU.json" -logFile ".\logfile.log"

.\gecko.ps1 -configFile ".\usercfg.json" -logFile ".\logfile.log" -CID "da-DK"

powershell.exe -NoLogo -ExecutionPolicy "Bypass" -File ".\gecko.ps1" -configFile ".\configC.json"
```

## Disclaimer

This is not an official repository, and is not affiliated with Microsoft, the **Windows gecko** repository is not affiliated with or endorsed by Microsoft. The names of actual companies and products mentioned herein may be the trademarks of their respective owners. All trademarks are the property of their respective companies.

## Legal and Licensing

**Windows gecko** is licensed under the [MIT license](./license 'MIT license').

The information and data of this repository and its contents are subject to change at any time without notice to you. This repository and its contents are provided **AS IS** without warranty of any kind and should not be interpreted as an offer or commitment on the part of the author(s). The descriptions are intended as brief highlights to aid understanding, rather than as thorough coverage.

## Change log

See the project Wiki page for full change log information.

--Jesper

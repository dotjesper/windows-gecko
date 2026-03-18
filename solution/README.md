# Solution

This folder contains the core files for **Windows gecko** - a desired state configuration tool for Windows devices.

## Content

| File | Description |
| --- | --- |
| **config.json** | Default configuration file loaded when no `-configFile` parameter is specified. |
| **configC.json** | Configuration file template for computer (SYSTEM) context. |
| **configU.json** | Configuration file template for user (USER) context. |
| **gecko.ps1** | The Windows gecko script - the main engine that reads configuration and applies desired state. |
| **gecko-config.schema.json** | JSON schema for validating configuration files. |
| **gecko.wsb** | Windows Sandbox configuration file for isolated testing. |
| **gecko.xaml** | Reserved for future use. |

## Usage

Run Windows gecko with a configuration file:

```powershell
.\gecko.ps1 -configFile .\configC.json
```

For more information, see the [Windows gecko wiki](https://github.com/dotjesper/windows-gecko/wiki).

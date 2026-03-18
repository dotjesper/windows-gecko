# Contributing to Windows gecko

Thank you for your interest in contributing to **Windows gecko**! This project is a personal learning platform and open-source tool, and contributions of all kinds are welcome — from bug reports and feature ideas to code improvements and documentation updates.

## How to Contribute

### Reporting Issues

If you find a bug or have a feature request, please open an [issue](https://github.com/dotjesper/windows-gecko/issues) on GitHub. The repository provides structured issue forms to help you provide the right information:

- **[Bug Report](https://github.com/dotjesper/windows-gecko/issues/new?template=bug_report.yml)** — for reporting bugs or unexpected behavior. The form will guide you through providing reproduction steps, environment details, and log output.
- **[Feature Request](https://github.com/dotjesper/windows-gecko/issues/new?template=feature_request.yml)** — for suggesting new features or improvements. The form will help you describe the problem, proposed solution, and related module.

### Starting a Discussion

For general questions, ideas, or feedback that are not specific bugs or feature requests, please use [GitHub Discussions](https://github.com/dotjesper/windows-gecko/discussions). This is the best place to:

- Ask questions about usage or configuration.
- Share ideas for new features or improvements.
- Discuss best practices for deployment scenarios.

### Submitting Pull Requests

1. **Fork** the repository and create a new branch from `main`.
2. **Make your changes** in the new branch.
3. **Test your changes** thoroughly in a non-production environment before submitting.
4. **Submit a pull request** with a clear description of what you changed and why.

When you open a pull request, a template will be provided to help you describe your changes, link related issues, and confirm that your submission meets the project guidelines.

#### Pull Request Guidelines

- Keep changes focused — one pull request per feature or fix.
- Follow the existing code style and conventions used in the project.
- Ensure your changes are compatible with PowerShell 5.1.
- Ensure your changes work in both Full Language mode and Constrained Language mode (CLM) where applicable.
- Update documentation if your changes affect usage or parameters.
- Do not include sensitive or environment-specific information in your changes.
- **No policy enforcement settings** — Windows gecko is a desired state configuration tool, not a policy enforcement solution. Sample configurations or pull requests that include settings designed to restrict or prevent users from changing their configuration (e.g., policy-based registry keys) are likely to be declined. If you need to enforce policy settings, use a dedicated management solution such as Microsoft Intune or Group Policy.

## Code Style

- Use proper PowerShell cmdlet names instead of aliases (e.g., `Get-ChildItem` instead of `dir`).
- Follow the existing comment and region structure in the script.
- Use `Write-Log` for all logging within the script — do not use `Write-Host` or `Write-Output` for runtime messages.
- Ensure CMTrace/Intune Management Extension log compatibility is maintained.
- All code should work under [PowerShell Constrained Language Mode](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes/) (CLM). Avoid .NET type accelerators (except `[int]`, `[string]`, `[bool]`, `[array]`, `[version]`, `[IntPtr]`), `.GetEnumerator()`, string methods like `.Trim()`, and other constructs blocked by CLM. Use PowerShell operators instead. Where CLM compatibility is not possible, guard the code path with `$script:IsConstrainedLanguageMode` and handle it gracefully (e.g., log a warning and skip the operation).
- Run [PSScriptAnalyzer](https://learn.microsoft.com/powershell/module/psscriptanalyzer/) against your changes before submitting. Install it with `Install-Module -Name PSScriptAnalyzer` and run `Invoke-ScriptAnalyzer -Path .\gecko.ps1` to check for issues.
- This project uses an [.editorconfig](./.editorconfig) file to enforce consistent formatting. Most editors, including Visual Studio Code, support EditorConfig natively.

## Testing

Before submitting any changes, please:

- Test with a valid configuration file (JSON).
- Test in both SYSTEM and USER context where applicable.
- Verify that the log output is correct and properly formatted.
- Use `-Verbose` and `-WhatIf` (where supported) to validate behavior before applying changes.

## Code of Conduct

This is a personal development project shared with the community. Please respect the community sharing philosophy:

- Be respectful and constructive in all interactions.
- Keep discussions focused and on-topic.
- Acknowledge that this is an evolving project and be patient with responses.

## License

By contributing to **Windows gecko**, you agree that your contributions will be licensed under the [MIT License](./LICENSE).

## Questions?

If you have questions that are not covered here, feel free to reach out on [Bluesky](https://bsky.app/profile/dotjesper.bsky.social/) or visit [https://dotjesper.com/contact/](https://dotjesper.com/contact/).

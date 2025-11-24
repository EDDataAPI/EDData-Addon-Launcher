# Security Audit Report

## Summary
This document outlines potential security vulnerabilities found in the Elite Dangerous Addon Launcher V2 codebase during a comprehensive security review.

**Audit Date**: November 24, 2025
**Framework**: .NET 8.0
**Severity Levels**: Critical 🔴 | High 🟠 | Medium 🟡 | Low 🔵

---

## Critical Vulnerabilities

### 1. 🔴 Arbitrary Process Execution via UseShellExecute = true
**Severity**: CRITICAL
**Location**: MainWindow.xaml.cs (Multiple locations)
**Lines**: 640, 765, 738

**Issue**:
```csharp
// Line 765: Web App URL directly passed to shell
using (var proc = Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }))

// Line 640: ClickOnce shortcut path
ProcessStartInfo(shortcutPath) { UseShellExecute = true }

// Line 738: Application path and arguments
ProcessStartInfo(path) { Arguments = args, UseShellExecute = true }
```

**Risk**:
- `UseShellExecute = true` allows arbitrary command execution if app paths contain shell metacharacters
- User-controlled application paths could execute malicious commands
- Command injection possible through app arguments

**Example Attack**:
```
App Path: C:\Path\app.exe
Injected: C:\Path\app.exe & malicious.exe
```

**Recommendation**:
- Set `UseShellExecute = false` for all Process.Start calls
- Use absolute paths only
- Validate file paths exist before execution
- Disable argument expansion for user-controlled parameters

---

### 2. 🔴 Unsafe JSON Deserialization without Type Validation
**Severity**: CRITICAL
**Location**: MainWindow.xaml.cs (Line 167)
**File**: Data stored in `%LocalAppData%\profiles.json`

**Issue**:
```csharp
List<Profile> loadedProfiles = JsonConvert.DeserializeObject<List<Profile>>(json);
```

**Risk**:
- No type name handling configuration in JsonConvert settings
- Potential deserialization of arbitrary .NET types
- Could lead to gadget chain attacks (if Newtonsoft.Json is old version)
- Malicious JSON could instantiate arbitrary types

**Attack Vector**:
```json
{
  "$type": "System.Diagnostics.Process, System",
  "StartInfo": { "FileName": "cmd.exe" }
}
```

**Recommendation**:
```csharp
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None,
    ConstructorHandling = ConstructorHandling.Default
};
List<Profile> loadedProfiles = JsonConvert.DeserializeObject<List<Profile>>(json, settings);
```

---

### 3. 🔴 Path Traversal in Application Installation Path
**Severity**: CRITICAL
**Location**: MainWindow.xaml.cs
**Lines**: 404, 631, 742

**Issue**:
```csharp
string exePath = Path.Combine(appToEdit.Path, appToEdit.ExeName);  // Line 404
var shortcutPath = Path.Combine(app.Path, app.ExeName);             // Line 631
```

**Risk**:
- User-controlled `Path` and `ExeName` without validation
- `..` sequences could escape intended directory
- Path traversal could execute arbitrary executables
- No validation that file is within expected directory

**Example Attack**:
```
Path: C:\Programs\
ExeName: ..\..\..\..\Windows\System32\cmd.exe
Result: C:\Windows\System32\cmd.exe
```

**Recommendation**:
```csharp
private bool IsPathWithinBasePath(string fullPath, string basePath)
{
    var fullInfo = new FileInfo(fullPath);
    var baseInfo = new DirectoryInfo(basePath);
    
    return fullInfo.FullName.StartsWith(
        baseInfo.FullName + Path.DirectorySeparatorChar,
        StringComparison.OrdinalIgnoreCase);
}

// Usage
if (!IsPathWithinBasePath(exePath, appToEdit.Path))
    throw new InvalidOperationException("Path traversal detected");
```

---

### 4. 🔴 Hardcoded Paths and Credentials
**Severity**: CRITICAL
**Location**: Services/LegendaryConfigManager.cs (Lines 18-20)
**Location**: MainWindow.xaml.cs (Line 1507)

**Issue**:
```csharp
// Hardcoded Epic Games manifest path
string manifestDir = @"C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests";

// Config file paths hardcoded
public static string ConfigPath => Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    ".config",
    "legendary",
    "config.ini");
```

**Risk**:
- Hardcoded paths vulnerable to elevation of privilege attacks
- Known paths can be targeted by malware
- No validation of directory ownership
- Could allow DLL injection or TOCTOU attacks

**Recommendation**:
```csharp
// Validate directory ownership
private bool IsDirectoryOwnedBySystem(string path)
{
    try
    {
        var info = new DirectoryInfo(path);
        var security = info.GetAccessControl();
        // Verify ownership by SYSTEM or trusted account
        return true;
    }
    catch { return false; }
}
```

---

## High-Severity Vulnerabilities

### 5. 🟠 Unvalidated File Read from User-Controlled Path
**Severity**: HIGH
**Location**: MainWindow.xaml.cs (Line 1524)
**Issue**:
```csharp
var json = File.ReadAllText(file);  // Epic manifest reading
```

**Risk**:
- Reads entire file into memory without size validation
- Potential DoS through large files
- No encoding validation
- Could cause out-of-memory crashes

**Recommendation**:
```csharp
const long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
var fileInfo = new FileInfo(file);
if (fileInfo.Length > MAX_FILE_SIZE)
    throw new InvalidOperationException("File too large");

var json = File.ReadAllText(file, Encoding.UTF8);
```

---

### 6. 🟠 Empty Exception Handlers Hiding Security Issues
**Severity**: HIGH
**Location**: MainWindow.xaml.cs (Line 1546)
**Issue**:
```csharp
catch
{
    // Skip corrupt manifest
}
```

**Risk**:
- Silently ignores all exceptions including SecurityException
- Access denied attacks go unnoticed
- Potential exploitation of privilege escalation
- Difficult to detect security breaches

**Recommendation**:
```csharp
catch (JsonException ex)
{
    Log.Warning("Invalid JSON in manifest {file}: {message}", file, ex.Message);
}
catch (IOException ex)
{
    Log.Warning("Cannot read manifest {file}: {message}", file, ex.Message);
}
catch (UnauthorizedAccessException ex)
{
    Log.Error("Access denied to manifest {file}: {message}", file, ex.Message);
}
```

---

### 7. 🟠 No Input Validation for Application Arguments
**Severity**: HIGH
**Location**: MainWindow.xaml.cs (Line 738)
**Issue**:
```csharp
Arguments = args,  // Line 722
// 'args' comes from user-defined app.Args without validation
```

**Risk**:
- User can inject arbitrary command-line arguments
- Potential command injection if arguments passed to shell
- Could override executable behavior
- Environment variable expansion possible

**Recommendation**:
```csharp
private bool IsValidArgument(string arg)
{
    // Whitelist allowed characters
    return Regex.IsMatch(arg, @"^[a-zA-Z0-9\s\-_.\/:\\""']*$");
}

if (!app.Args.Split(' ').All(IsValidArgument))
    throw new InvalidOperationException("Invalid arguments");

var info = new ProcessStartInfo(path) {
    Arguments = EscapeArguments(app.Args),
    UseShellExecute = false  // IMPORTANT!
};
```

---

### 8. 🟠 Unvalidated Web URLs
**Severity**: HIGH
**Location**: MainWindow.xaml.cs (Line 765)
**Issue**:
```csharp
string target = app.WebAppURL;
using (var proc = Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }))
```

**Risk**:
- No URL validation before passing to shell
- Could execute arbitrary local commands if malicious URL provided
- No protocol validation
- `file://`, `javascript:`, etc. could be exploited

**Example Attack**:
```
URL: file:///c:/windows/system32/cmd.exe
Result: cmd.exe executed via shell
```

**Recommendation**:
```csharp
private bool IsValidWebUrl(string url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        return false;
    
    // Only allow http/https
    return uri.Scheme is "http" or "https";
}

if (!IsValidWebUrl(app.WebAppURL))
    throw new InvalidOperationException("Invalid URL");
```

---

## Medium-Severity Vulnerabilities

### 9. 🟡 Sensitive Data in Plaintext Files
**Severity**: MEDIUM
**Location**: MainWindow.xaml.cs (Line 208)
**File**: `%LocalAppData%\profiles.json`

**Issue**:
```csharp
string path = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
    AppConstants.ProfilesFileName);
```

**Risk**:
- Stores application paths and arguments in plaintext
- Located in user-accessible directory
- Could contain sensitive paths or credentials
- No encryption applied
- Other local users can read the file

**Recommendation**:
```csharp
private const string PROFILES_FILENAME_ENCRYPTED = "profiles.dat";

private byte[] EncryptData(string data)
{
    using (var dph = new DataProtectionProvider())
    {
        return dph.Protect(Encoding.UTF8.GetBytes(data));
    }
}

// Encrypt sensitive profile data before saving
var encryptedData = EncryptData(profilesJson);
File.WriteAllBytes(path, encryptedData);
```

---

### 10. 🟡 No Version Control for Profile Files
**Severity**: MEDIUM
**Location**: MainWindow.xaml.cs (Line 207-209)

**Risk**:
- Profile files could be silently corrupted or replaced
- No integrity verification
- Malicious profile injection possible
- No rollback mechanism

**Recommendation**:
```csharp
// Add hash verification
private string ComputeFileHash(string filePath)
{
    using (var sha256 = System.Security.Cryptography.SHA256.Create())
    {
        using (var stream = File.OpenRead(filePath))
        {
            var hash = sha256.ComputeHash(stream);
            return Convert.ToHexString(hash);
        }
    }
}

// Store hash alongside profile
var profileData = new { 
    profiles = profiles, 
    hash = ComputeFileHash(jsonContent) 
};
```

---

## Low-Severity Vulnerabilities

### 11. 🔵 Process Handle Not Always Disposed
**Severity**: LOW
**Location**: MainWindow.xaml.cs (Line 742)
**Issue**:
```csharp
Process proc = Process.Start(info);  // Partially fixed with using
proc.EnableRaisingEvents = true;
```

**Risk**:
- Even with using statement, handle leak if exception before using
- Process resource exhaustion possible

**Already Partially Fixed**: Using statements added in recent optimization

---

### 12. 🔵 Logging of Sensitive Information
**Severity**: LOW
**Location**: MainWindow.xaml.cs (Multiple locations)
**Issue**:
```csharp
Log.Information("Launching {AppName}..", app.Name);
```

**Risk**:
- Could log sensitive application paths in future
- Log files stored in plaintext
- No log rotation or cleanup

**Recommendation**:
```csharp
// Be careful not to log full paths
Log.Information("Launching app");

// Never log:
// - Full file paths
// - User credentials
// - API keys
// - Database connection strings
```

---

## Summary Table

| ID | Vulnerability | Severity | Status | Effort |
|----|---------------|----------|--------|--------|
| 1 | UseShellExecute = true | 🔴 CRITICAL | Unfixed | High |
| 2 | Unsafe JSON Deserialization | 🔴 CRITICAL | Unfixed | Low |
| 3 | Path Traversal | 🔴 CRITICAL | Unfixed | High |
| 4 | Hardcoded Paths | 🔴 CRITICAL | Unfixed | Medium |
| 5 | Unvalidated File Read | 🟠 HIGH | Unfixed | Low |
| 6 | Empty Exception Handlers | 🟠 HIGH | Partially Fixed | Low |
| 7 | Unvalidated Arguments | 🟠 HIGH | Unfixed | Medium |
| 8 | Unvalidated URLs | 🟠 HIGH | Unfixed | Low |
| 9 | Plaintext Sensitive Data | 🟡 MEDIUM | Unfixed | High |
| 10 | No Profile Integrity Check | 🟡 MEDIUM | Unfixed | Medium |
| 11 | Process Handle Leak | 🔵 LOW | Partially Fixed | Low |
| 12 | Sensitive Logging | 🔵 LOW | Unfixed | Low |

---

## Recommended Priority Order

### Phase 1 (Immediate - Critical)
1. ❗ Fix UseShellExecute vulnerability (Issue #1)
2. ❗ Add JSON deserialization settings (Issue #2)
3. ❗ Implement path traversal protection (Issue #3)

### Phase 2 (High Priority)
4. Add argument validation (Issue #7)
5. Add URL validation (Issue #8)
6. Add file size validation (Issue #5)

### Phase 3 (Medium Priority)
7. Encrypt profile files (Issue #9)
8. Add profile integrity verification (Issue #10)
9. Improve exception handling (Issue #6)

### Phase 4 (Low Priority)
10. Audit logging practices (Issue #12)

---

## Code Review Checklist

- [ ] All Process.Start calls use UseShellExecute = false
- [ ] All file paths validated before use
- [ ] JSON deserialization uses secure settings
- [ ] User arguments sanitized
- [ ] URLs validated before opening
- [ ] File sizes validated before reading
- [ ] Sensitive files encrypted (profiles.json)
- [ ] Exception handlers specific (not bare catch)
- [ ] No credentials in code or logs
- [ ] File integrity verification in place

---

## Compliance Notes

- **OWASP Top 10**: Vulnerabilities align with A03:2021 Injection, A04:2021 Insecure Deserialization
- **CWE References**: 
  - CWE-78: Improper Neutralization of Special Elements used in an OS Command
  - CWE-22: Improper Limitation of a Pathname to a Restricted Directory
  - CWE-502: Deserialization of Untrusted Data

---

## Disclaimer

This audit identifies potential vulnerabilities. Actual exploitability depends on:
- User permissions
- System configuration
- Network exposure
- User behavior

This is a desktop application with local file access, reducing but not eliminating risks.

---

**Report Generated**: November 24, 2025
**Auditor**: Code Security Review
**Framework**: .NET 8.0
**Status**: Requires Remediation

# Windows Update Deep Disable/Enable Script

![Windows Update Control](https://example.com/banner_image.png)

## 🚀 Version: 3.3

### 🎨 Table of Contents
1. [Introduction](#introduction)
2. [Features](#features)
3. [Usage](#usage)
4. [How It Works](#how-it-works)
5. [Requirements](#requirements)
6. [Disclaimer](#disclaimer)
7. [Contributing](#contributing)
8. [License](#license)

---

## 🔍 Introduction
The **Windows Update Deep Disable/Enable Script** is a versatile PowerShell tool for managing Windows Update settings on **Windows 11 Enterprise** systems. Designed primarily for educational purposes, it allows users to comprehensively disable or re-enable update-related features with minimal hassle.

Whether you need to block updates to maintain system stability or restore full update functionality, this script has you covered.

---

## ✨ Features
- **Deep Update Disabling:**
  - Direct registry edits to disable update-related services.
  - Disables scheduled tasks related to Windows Update.
  - Applies group policies to block update access.
  - Adds entries to the hosts file to block Microsoft Update endpoints.
  - Implements outbound firewall rules to block known Windows Update IPs.

- **Easy Re-enabling:**
  - Restores services to their original states.
  - Enables scheduled tasks previously disabled.
  - Removes registry policies, hosts entries, and firewall rules.

- **Non-Invasive:**
  - No permanent deletions; all changes are reversible.

---

## 🛠️ Usage

### Running the Script
1. Open PowerShell as an Administrator.
2. Navigate to the folder containing the script.
3. Execute the script with the appropriate option:
   ```powershell
   .\disablewindows_update_1.3.ps1
   ```

### Parameters
- `-Disable`
  Disables Windows Update functionality.

- `-Enable`
  Restores Windows Update functionality.

### Example:
```powershell
# To disable updates
.\disablewindows_update_1.3.ps1 -Disable

# To enable updates
.\disablewindows_update_1.3.ps1 -Enable
```

---

## ⚙️ How It Works
### **Disabling Updates**
1. **Registry Changes:** Updates the `Start` values of update-related services to prevent them from starting.
2. **Task Scheduler:** Disables tasks tied to Windows Update.
3. **Group Policies:** Applies policies to block update access.
4. **Hosts File:** Adds entries to block connections to known Microsoft update servers.
5. **Firewall Rules:** Adds outbound rules to block update-related IPs.

### **Enabling Updates**
1. Restores original `Start` values for services.
2. Enables previously disabled scheduled tasks.
3. Removes applied group policies, hosts entries, and firewall rules.

---

## 💻 Requirements
- Windows 11 Enterprise (Education version supported).
- Administrator privileges.
- PowerShell 5.1 or higher.

---

## ⚠️ Disclaimer
This script is provided **AS IS** without any warranty. Use at your own risk. Modifying system-level settings can lead to unforeseen issues. Always back up critical data and configurations before use.

---

## 🤝 Contributing
We welcome contributions to improve this script and its documentation. If you have suggestions or encounter issues, please:
1. Fork the repository.
2. Make your changes.
3. Submit a pull request.

---

## 📜 License
This project is licensed under the [MIT License](LICENSE).

---

Feel free to reach out if you have questions, feedback, or need assistance!

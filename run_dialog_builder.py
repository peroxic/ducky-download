import base64

def create_run_command(encoded_command):
    # Format the command for execution in the Run dialog
    run_command = f'powershell -w hidden -Enc {encoded_command}'
    return run_command

def main():
    # Prompt the user for the Base64-encoded command
    encoded_command = input("Enter the Base64-encoded PowerShell command: ").strip()

    # Validate the input
    if not encoded_command:
        print("Error: No command provided.")
        return

    # Create the formatted command
    run_command = create_run_command(encoded_command)

    # Print the command for the user
    print("\nYou can run the following command in the Windows Run dialog (Win + R):")
    print(run_command)

if __name__ == "__main__":
    main()

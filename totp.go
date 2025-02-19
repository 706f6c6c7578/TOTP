package main

import (
    "bufio"
    "fmt"
    "os"
    "time"

    "github.com/pquerna/otp"
    "github.com/pquerna/otp/totp"
    "flag"
)

// Display the key information (Issuer, Account Name, Secret)
func display(key *otp.Key) {
    fmt.Printf("Issuer:       %s\n", key.Issuer())
    fmt.Printf("Account Name: %s\n", key.AccountName())
    fmt.Printf("Secret:       %s\n", key.Secret())
}

// Prompt the user for input
func promptForInput(prompt string) string {
    reader := bufio.NewReader(os.Stdin)
    fmt.Print(prompt)
    text, _ := reader.ReadString('\n')
    return text
}

// GeneratePassCode generates the current TOTP passcode based on the secret.
func GeneratePassCode(secret string, skew uint, algorithm otp.Algorithm, digits otp.Digits) (string, error) {
    return totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
        Period:    30,
        Skew:      skew,
        Digits:    digits,
        Algorithm: algorithm,
    })
}

// ValidatePassCode checks if the provided passcode is valid.
func ValidatePassCode(passcode, secret string, skew uint, algorithm otp.Algorithm, digits otp.Digits) bool {
    valid, err := totp.ValidateCustom(passcode, secret, time.Now(), totp.ValidateOpts{
        Period:    30,
        Skew:      skew,
        Digits:    digits,
        Algorithm: algorithm,
    })
    if err != nil {
        return false
    }
    return valid
}

func main() {
    // Flags for Issuer, Account Name, Skew, Algorithm, and Digits
    issuer := flag.String("issuer", "example.com", "The issuer for the TOTP key")
    accountName := flag.String("account", "user@example.com", "The account name for the TOTP key")
    skew := flag.Int("skew", 1, "The skew value for TOTP validation (default: 1)")
    algorithm := flag.String("algorithm", "SHA1", "The hashing algorithm to use (SHA1, SHA256, SHA512)")
    digits := flag.Int("digits", 6, "The number of digits in the passcode (6 or 8, default: 6)")

    flag.Parse()

    // Convert the algorithm flag to an otp.Algorithm type
    var algo otp.Algorithm
    switch *algorithm {
    case "SHA1":
        algo = otp.AlgorithmSHA1
    case "SHA256":
        algo = otp.AlgorithmSHA256
    case "SHA512":
        algo = otp.AlgorithmSHA512
    default:
        fmt.Println("Invalid algorithm. Supported values are SHA1, SHA256, and SHA512.")
        os.Exit(1)
    }

    // Convert the digits flag to an otp.Digits type
    var digitType otp.Digits
    switch *digits {
    case 6:
        digitType = otp.DigitsSix
    case 8:
        digitType = otp.DigitsEight
    default:
        fmt.Println("Invalid number of digits. Supported values are 6 or 8.")
        os.Exit(1)
    }

    // Main loop to keep the program running
    for {
        // Menu for selecting functionality
        fmt.Println("\nTOTP Authentication Tool")
        fmt.Println("1. Generate a new shared secret")
        fmt.Println("2. Generate a passcode")
        fmt.Println("3. Validate a passcode")
        fmt.Println("4. Exit")

        choice := promptForInput("Enter your choice: ")
        switch choice {
        case "1\n":
            // Option 1: Generate a new shared secret
            key, err := totp.Generate(totp.GenerateOpts{
                Issuer:      *issuer,
                AccountName: *accountName,
                Algorithm:   algo, // Use the selected algorithm
            })
            if err != nil {
                fmt.Println("Error generating shared secret:", err)
                continue
            }
            display(key)
            fmt.Println("Share this secret with the other party.")

        case "2\n":
            // Option 2: Generate a passcode
            secret := promptForInput("Enter the shared secret: ")
            passcode, err := GeneratePassCode(secret, uint(*skew), algo, digitType)
            if err != nil {
                fmt.Println("Error generating passcode:", err)
                continue
            }
            fmt.Printf("Current Passcode: %s\n", passcode)

        case "3\n":
            // Option 3: Validate a passcode
            secret := promptForInput("Enter the shared secret: ")
            passcode := promptForInput("Enter the passcode to validate: ")
            if ValidatePassCode(passcode, secret, uint(*skew), algo, digitType) {
                fmt.Println("Valid passcode!")
            } else {
                fmt.Println("Invalid passcode!")
            }

        case "4\n":
            // Option 4: Exit
            fmt.Println("Exiting...")
            os.Exit(0)

        default:
            fmt.Println("Invalid choice. Please try again.")
        }

        // Wait for further input before showing the menu again
        fmt.Println("\nPress Enter to continue...")
        promptForInput("")
    }
}
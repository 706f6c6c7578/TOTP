package main

import (
    "bufio"
    "crypto/sha256"
    "encoding/base32"
    "fmt"
    "os"
    "time"

    "github.com/pquerna/otp"
    "github.com/pquerna/otp/totp"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/hkdf"
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

// GenerateDeterministicSecret creates a deterministic secret using Argon2id and HKDF
func GenerateDeterministicSecret(password, salt string) string {
    // Argon2id parameters
    time := uint32(1)
    memory := uint32(64 * 1024)
    threads := uint8(4)
    keyLen := uint32(32)

    // Generate key using Argon2id
    argonKey := argon2.IDKey([]byte(password), []byte(salt), time, memory, threads, keyLen)

    // Use HKDF to derive the final key
    hkdfReader := hkdf.New(sha256.New, argonKey, []byte(salt), []byte("TOTP-Secret"))
    finalKey := make([]byte, 32)
    _, err := hkdfReader.Read(finalKey)
    if err != nil {
        return ""
    }

    // Encode to base32 as required by TOTP
    encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(finalKey)
    return encoded[:32]
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
    skew := flag.Int("skew", 1, "The skew value for TOTP validation: 1 equals 30 seconds")
    algorithm := flag.String("algorithm", "SHA1", "The hashing algorithm to use (SHA1, SHA256, SHA512)")
    digits := flag.Int("digits", 6, "The number of digits in the passcode (6 or 8)")

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
            fmt.Println("\nChoose secret generation method:")
            fmt.Println("a. Random (standard)")
            fmt.Println("b. Deterministic (using password and salt)")
            
            genChoice := promptForInput("Enter your choice (a/b): ")
            
            switch genChoice {
            case "a\n":
                key, err := totp.Generate(totp.GenerateOpts{
                    Issuer:      *issuer,
                    AccountName: *accountName,
                    Algorithm:   algo,
                })
                if err != nil {
                    fmt.Println("Error generating shared secret:", err)
                    continue
                }
                display(key)
                fmt.Println("Share this secret with the other party.")
                
            case "b\n":
                password := promptForInput("Enter password: ")
                salt := promptForInput("Enter salt: ")
                
                secret := GenerateDeterministicSecret(password[:len(password)-1], salt[:len(salt)-1])
                
                key, err := totp.Generate(totp.GenerateOpts{
                    Issuer:      *issuer,
                    AccountName: *accountName,
                    Secret:      []byte(secret),
                    Algorithm:   algo,
                })
                if err != nil {
                    fmt.Println("Error generating shared secret:", err)
                    continue
                }
                display(key)
                fmt.Println("Share the password and salt with the other party.")
            
            default:
                fmt.Println("Invalid choice")
            }

        case "2\n":
            secret := promptForInput("Enter the shared secret: ")
            passcode, err := GeneratePassCode(secret[:len(secret)-1], uint(*skew), algo, digitType)
            if err != nil {
                fmt.Println("Error generating passcode:", err)
                continue
            }
            fmt.Printf("Current Passcode: %s\n", passcode)

        case "3\n":
            secret := promptForInput("Enter the shared secret: ")
            passcode := promptForInput("Enter the passcode to validate: ")
            if ValidatePassCode(passcode[:len(passcode)-1], secret[:len(secret)-1], uint(*skew), algo, digitType) {
                fmt.Println("Valid passcode!")
            } else {
                fmt.Println("Invalid passcode!")
            }

        case "4\n":
            fmt.Println("Exiting...")
            os.Exit(0)

        default:
            fmt.Println("Invalid choice. Please try again.")
        }

        fmt.Println("\nPress Enter to continue...")
        promptForInput("")
    }
}

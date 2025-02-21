$ totp -h
Usage of totp:
  -account string
        The account name for the TOTP key (default "user@example.com")
  -algorithm string
        The hashing algorithm to use (SHA1, SHA256, SHA512) (default "SHA1")
  -digits int
        The number of digits in the passcode (6 or 8) (default 6)
  -issuer string
        The issuer for the TOTP key (default "example.com")
  -skew int
        The skew value for TOTP validation: 1 equals 30 seconds (default 1)
$ totp

TOTP Authentication Tool
1. Generate a new shared secret
2. Generate a passcode
3. Validate a passcode
4. Exit
Enter your choice:

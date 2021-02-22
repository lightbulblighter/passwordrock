# PasswordRock
Rock-solid PHP password hashing algorithm

This is really just a fork of [paragonie/password_lock](https://github.com/paragonie/password_lock). The core implementation is still the same, with the only changes being that it now hashes using Argon2 rather than BCrypt and also has support for `Defuse\Crypto\KeyProtectedByPassword`.

## Caution
Please note that this library isn't peer-reviewed and extensively tested as other cryptographic libraries are. If you want to ensure maximum security, please use Paragon's password_lock library.

This library encrypts password hashes in such a way that the original password is the only way possible to unlock the ciphertext to grab the hash. There is no possible way to get the hash without complete and total knowledge of the users password. A side-effect of this is that the computationally expensive method `KeyProtectedByPassword::unlockKey` is called each time a password is locked or verified. However, there is no burden of having a "master password" stored that could be compromised and have password hashes revealed.

## Usage
Example account creation code using PasswordRock:
```php
use \lightbulblighter\PasswordRock;

$password = trim($_POST["password"]);
if (empty($password))
{
    exit("No password given");
}

$locked = PasswordRock::lock($password); // this is an associative array
// ... store $locked["ciphertext"], $locked["salt"], and $locked["key"] in your database
```

Example account sign-in code using PasswordRock that ties in with the account creation code:
```php
use \lightbulblighter\PasswordRock;

$username = trim($_POST["username"]);
$password = trim($_POST["password"]);

if (empty($username) || empty($password))
{
    exit("Insufficient login details");
}

// ... fetch "ciphertext", "salt" and "key" from the database for the user $username
// ... put them in an associative array named $locked

if (PasswordRock::verify($password, $locked))
{
    exit("Hi, $username!");
}
else
{
    exit("Wrong username or password");
}
```

## Implementation
Locking:
1. Create random secret key protected by password
2. Create random salt
3. Append salt to end of password
4. Hash password using Argon2-base64-SHA512
5. Encrypt-then-MAC the hash using the random secret key

Verification:
1. Try unlocking protected key with password
2. VerifyHMAC-then-Decrypt the ciphertext to get the hash
3. Verify that the password matches the hash

## License
This is free and unencumbered software released into the public domain. You may read the full license [here](https://github.com/lightbulblighter/blob/master/LICENSE) for more information.
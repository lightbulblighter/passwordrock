<?php
declare(strict_types=1);
namespace lightbulblighter\PasswordRock;

use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\KeyProtectedByPassword;
use \Defuse\Crypto\Core;
use \ParagonIE\ConstantTime\Base64;

class PasswordRock
{
    const SALT_LENGTH = 128;

    /**
     * Returns a randomly generated salt.
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    private static function generateSalt()
    {
        return Core::secureRandom(self::SALT_LENGTH);
    }

    /**
     * Locks a password
     *
     * @param string $password
     * @param bool $salt_key (default: false)
     *
     * @throws \Exception
     *
     * @return array
     */
    public static function lock($password, $salt_key = false)
    {
        $salt = self::generateSalt();
        $hash = \password_hash(
            Base64::encode(
                \hash('sha512', ($password . $salt), true)
            ),
            PASSWORD_ARGON2ID
        );
        if (!\is_string($hash))  {
            throw new \Exception('Unknown hashing error.');
        }
        if ($salt_key) {
            $password .= $salt;
        }
        $key = KeyProtectedByPassword::createRandomPasswordProtectedKey($password);

        return [
            'ciphertext' => Crypto::encrypt($hash, $key->unlockKey($password)),
            'salt' => $salt,
            'key' => $key->saveToAsciiSafeString()
        ];
    }

    /**
     * Verifies a password
     *
     * @param string $password
     * @param array $locked
     * @param bool $key_password_is_salted (default: false)
     *
     * @throws \Exception
     * @throws \InvalidArgumentException
     *
     * @return bool
     */
    public static function verify($password, $locked, $key_password_is_salted = false)
    {
        if (!\isset($locked['ciphertext'], $locked['salt'], $locked['key'])) {
            throw new \InvalidArgumentException('Not all values required for password verification were found.');
        }
        $hash = Crypto::decrypt(
            $locked['ciphertext'],
            $locked['key']->unlockKey($password . ($key_password_is_salted ? $locked['salt'] : ''))
        );
        if (!\is_string($hash)) {
            throw new \Exception('Unknown hashing error.');
        }
        return \password_verify(
            Base64::encode(
                \hash('sha512', ($password . $locked['salt']), true)
            ),
            $hash
        );
    }
}
<?php

declare(strict_types=1);

/**
 * PHP Class for handling Google Authenticator 2-factor authentication.
 *
 * @author Michael Kliewe
 * @copyright 2012 Michael Kliewe
 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
 * @link http://www.phpgangsta.de/
 */
class PHPGangsta_GoogleAuthenticator
{
    private const BASE32_CHARS = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', '2', '3', '4', '5', '6', '7',
        '=',
    ];

    protected int $codeLength = 6;

    /**
     * Creates a new random secret for authentication.
     * 16 characters, randomly chosen from the allowed base32 characters.
     *
     * @param int $secretLength
     *
     * @return string
     * @throws LengthException If secret length is invalid
     */
    public function createSecret(int $secretLength = 16): string
    {
        if ($secretLength < 16 || $secretLength > 128) {
            throw new LengthException("Secret length must be between 16 and 128 characters");
        }

        $bytes = random_bytes($secretLength);
        $secret = '';
        $lookup = self::BASE32_CHARS;

        for ($i = 0; $i < $secretLength; $i++) {
            $secret .= $lookup[ord($bytes[$i]) & 31];
        }

        return $secret;
    }

    /**
     * Generates a time-based one-time password.
     *
     * @param string   $secret
     * @param int|null $timeSlice
     *
     * @return string
    */
    public function getCode(string $secret, ?int $timeSlice = null): string
    {
        $timeSlice ??= (int) (time() / 30);
        $secretKey = $this->base32Decode($secret);
        $time = pack('N', 0) . pack('N', $timeSlice); // 8-byte time value
        $hash = hash_hmac('SHA1', $time, $secretKey, true);
        $offset = ord($hash[-1]) & 0x0F;
        $value = unpack('N', substr($hash, $offset, 4))[1] & 0x7FFFFFFF;

        return str_pad((string) ($value % 10 ** $this->codeLength), $this->codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * Returns URL for QR code generation.
     *
     * @param string $name
     * @param string $secret
     * @param string|null $title
     * @param array<string, mixed> $params
     *
     * @return string
     */
    public function getQRCodeGoogleUrl(string $name, string $secret, ?string $title = null, array $params = []): string
    {
        $width = max((int) ($params['width'] ?? 200), 1);
        $height = max((int) ($params['height'] ?? 200), 1);
        $level = in_array($params['level'] ?? 'M', ['L', 'M', 'Q', 'H']) ? $params['level'] : 'M';

        $data = "otpauth://totp/" . urlencode($name) . "?secret=" . urlencode($secret);
        if ($title !== null) {
            $data .= "&issuer=" . urlencode($title);
        }

        return "https://api.qrserver.com/v1/create-qr-code/?data={$data}&size={$width}x{$height}&ecc={$level}";
    }

    /**
     * Verifies a code against the secret with allowed time drift.
     *
     * @param string   $secret
     * @param string   $code
     * @param int      $discrepancy
     * @param int|null $currentTimeSlice
     *
     * @return bool
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1, ?int $timeSlice = null): bool
    {
        $timeSlice ??= (int) (time() / 30);
        if (strlen($code) !== 6) {
            return false;
        }

        foreach (range(-$discrepancy, $discrepancy) as $offset) {
            if (hash_equals($this->getCode($secret, $timeSlice + $offset), $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Set the code length, should be >=6.
     *
     * @param int $length
     *
     * @return self
     */
    public function setCodeLength(int $length): self
    {
        $this->codeLength = $length;
        return $this;
    }

    /**
     * Decodes a base32 string to binary.
     *
     * @param string $secret
     *
     * @return string
     */
    protected function base32Decode(string $secret): string
    {
        if (empty($secret)) {
            return '';
        }

        $lookup = array_flip(self::BASE32_CHARS);
        $paddingCount = substr_count($secret, '=');
        $allowedPadding = [6, 4, 3, 1, 0];

        if (!in_array($paddingCount, $allowedPadding, true)) {
            return '';
        }

        $secret = str_replace('=', '', $secret);
        $chars = str_split($secret);
        $binary = '';

        for ($i = 0; $i < count($chars); $i += 8) {
            $bits = '';
            if (!isset($lookup[$chars[$i]])) {
                return '';
            }

            for ($j = 0; $j < 8 && isset($chars[$i + $j]); $j++) {
                $bits .= str_pad(decbin($lookup[$chars[$i + $j]] ?? 0), 5, '0', STR_PAD_LEFT);
            }

            foreach (str_split($bits, 8) as $byte) {
                if (strlen($byte) === 8) {
                    $binary .= chr(bindec($byte));
                }
            }
        }

        return $binary;
    }
}
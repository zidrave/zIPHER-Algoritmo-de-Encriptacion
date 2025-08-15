<?php
$start_time = microtime(true); // Inicio del contador
// toy_stream_secure_v4_optimized.php — Optimizado manteniendo todas las características

function keystream_generate($key_stream, $nonce, $length) {
    // Generar keystream por bloques de 64 bytes
    $ks = '';
    $counter = 0;
    while (strlen($ks) < $length) {
        $data = $nonce . pack('N', $counter);
        $ks .= hash_hmac('sha512', $data, $key_stream, true);
        $counter++;
    }
    return substr($ks, 0, $length);
}

function add_random_padding($plaintext, $blockSize = 16) {
    $pad_len = $blockSize - (strlen($plaintext) % $blockSize);
    $pad_len += random_int(0, $blockSize); // padding extra aleatorio
    return $plaintext . random_bytes($pad_len);
}

function permute_bytes($data, $ks) {
    $length = strlen($data);
    $indices = range(0, $length-1);
    $ks_ord = array_map('ord', str_split($ks));
    for ($i = 0; $i < $length; $i++) {
        $swap = $ks_ord[$i % count($ks_ord)] % $length;
        $tmp = $indices[$i];
        $indices[$i] = $indices[$swap];
        $indices[$swap] = $tmp;
    }
    $permuted = '';
    for ($i = 0; $i < $length; $i++) $permuted .= $data[$indices[$i]];
    return $permuted;
}

function unpermute_bytes($data, $ks) {
    $length = strlen($data);
    $indices = range(0, $length-1);
    $ks_ord = array_map('ord', str_split($ks));
    for ($i = 0; $i < $length; $i++) {
        $swap = $ks_ord[$i % count($ks_ord)] % $length;
        $tmp = $indices[$i];
        $indices[$i] = $indices[$swap];
        $indices[$swap] = $tmp;
    }
    $inverse = array_flip($indices);
    $original = '';
    for ($i = 0; $i < $length; $i++) $original .= $data[$inverse[$i]];
    return $original;
}

function encrypt_stream($plaintext, $key_stream, $key_mac, $nonce) {
    $orig_len = strlen($plaintext);
    $plaintext = add_random_padding($plaintext);
    $plaintext = gzcompress($plaintext);

    $ks = keystream_generate($key_stream, $nonce, strlen($plaintext));

    $xored = $plaintext ^ $ks; // XOR de strings completos con PHP >=7
    $permuted = permute_bytes($xored, $ks);

    $mac1 = hash_hmac('sha512', $permuted, $key_mac, true);
    $mac2 = hash_hmac('sha512', $permuted . $mac1, $key_mac, true);

    $len_bytes = pack('N', $orig_len);
    return $len_bytes . $permuted . $mac1 . $mac2;
}

function decrypt_stream($ciphertext_with_mac, $key_stream, $key_mac, $nonce) {
    $mac_len = 64;
    $len_bytes = substr($ciphertext_with_mac, 0, 4);
    $orig_len = unpack('N', $len_bytes)[1];

    $permuted_len = strlen($ciphertext_with_mac) - 4 - 2 * $mac_len;
    $ciphertext = substr($ciphertext_with_mac, 4, $permuted_len);
    $mac1 = substr($ciphertext_with_mac, 4 + $permuted_len, $mac_len);
    $mac2 = substr($ciphertext_with_mac, 4 + $permuted_len + $mac_len, $mac_len);

    $calc_mac1 = hash_hmac('sha512', $ciphertext, $key_mac, true);
    $calc_mac2 = hash_hmac('sha512', $ciphertext . $calc_mac1, $key_mac, true);

    if (!hash_equals($mac1, $calc_mac1) || !hash_equals($mac2, $calc_mac2)) {
        throw new Exception("ERROR: Integridad del ciphertext falló.");
    }

    $ks = keystream_generate($key_stream, $nonce, strlen($ciphertext));
    $unpermuted = unpermute_bytes($ciphertext, $ks);
    $plaintext_padded = $unpermuted ^ $ks;

    $decompressed = gzuncompress($plaintext_padded);
    return substr($decompressed, 0, $orig_len);
}

// --- Descifrado con soporte para segunda contraseña ---
function decrypt_stream_with_master($ciphertext_with_mac, $password, $master_password, $salt, $nonce) {
    $key_stream1 = hash_pbkdf2('sha512', $password, $salt . 'stream', 100000, 64, true);
    $key_mac1    = hash_pbkdf2('sha512', $password, $salt . 'mac', 100000, 64, true);

    try {
        return decrypt_stream($ciphertext_with_mac, $key_stream1, $key_mac1, $nonce);
    } catch (Exception $e) {
        $key_stream2 = hash_pbkdf2('sha512', $master_password, $salt . 'stream', 100000, 64, true);
        $key_mac2    = hash_pbkdf2('sha512', $master_password, $salt . 'mac', 100000, 64, true);
        return decrypt_stream($ciphertext_with_mac, $key_stream2, $key_mac2, $nonce);
    }
}

// --- Uso ---
$plain = "Mensaje secreto y muy importante.";
$password = "MiContraseñaUltraSegura";
$master_password = "clavemaestra";

$salt = random_bytes(32);
$nonce = random_bytes(24);

$key_stream = hash_pbkdf2('sha512', $password, $salt . 'stream', 100000, 64, true);
$key_mac    = hash_pbkdf2('sha512', $password, $salt . 'mac', 100000, 64, true);

$cipher = encrypt_stream($plain, $key_stream, $key_mac, $nonce);
$package = base64_encode($salt . $nonce . $cipher);

echo "Package: $package\n";

$decoded = base64_decode($package);
$salt2 = substr($decoded, 0, 32);
$nonce2 = substr($decoded, 32, 24);
$cipher2 = substr($decoded, 56);

$recovered = decrypt_stream_with_master($cipher2, $password, $master_password, $salt2, $nonce2);
echo "Recovered: $recovered\n";


$end_time = microtime(true); // Fin del contador
$elapsed = $end_time - $start_time;
echo "<br><br><br><hr>Página ejecutada en " . number_format($elapsed, 4) . " segundos\n<br><br><br>";

?>

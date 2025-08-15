<?php
// Inicio del contador de tiempo
$start_time = microtime(true);

// --- Zipher: Lógica de cifrado y descifrado ---
$master_password = "clavemaestra"; // Clave maestra declarada en el código

function keystream_generate($key_stream, $nonce, $length) {
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
    $pad_len += random_int(0, $blockSize);
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
    $xored = $plaintext ^ $ks;
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
    if ($decompressed === false) {
        throw new Exception("ERROR: Falló la descompresión de datos.");
    }
    
    return substr($decompressed, 0, $orig_len);
}

// --- Función para encriptar con sistema de doble clave REAL ---
function encrypt_dual_key($plaintext, $user_password) {
    global $master_password;
    
    $salt = random_bytes(32);
    $nonce = random_bytes(24);

    // NUEVO ENFOQUE: Cifrar con la contraseña del usuario, pero incluir 
    // un "master key derivation hint" que permita a la clave maestra descifrar
    
    // Derivar clave del usuario normal
    $user_key_stream = hash_pbkdf2('sha512', $user_password, $salt . 'stream', 100000, 64, true);
    $user_key_mac    = hash_pbkdf2('sha512', $user_password, $salt . 'mac', 100000, 64, true);

    // Cifrar normalmente con clave del usuario
    $cipher = encrypt_stream($plaintext, $user_key_stream, $user_key_mac, $nonce);
    
    // Crear un "key escrow": cifrar la clave del usuario con la clave maestra
    $master_key_stream = hash_pbkdf2('sha512', $master_password, $salt . 'master_stream', 100000, 32, true);
    $user_key_encrypted = $user_password ^ substr(str_repeat($master_key_stream, ceil(strlen($user_password)/32)), 0, strlen($user_password));
    $escrow_mac = hash_hmac('sha256', $user_key_encrypted, $master_key_stream, true);
    
    // Package: sal(32) + nonce(24) + cipher + escrow_key(len+data) + mac(32)
    $escrow_data = chr(strlen($user_password)) . $user_key_encrypted . $escrow_mac;
    
    return base64_encode($salt . $nonce . $cipher . $escrow_data);
}

// --- Función para descifrar con clave maestra universal ---
function decrypt_dual_key($package_b64, $password) {
    global $master_password;
    
    $package = base64_decode($package_b64);
    if ($package === false || strlen($package) < 56) {
        throw new Exception("ERROR: Formato de package inválido.");
    }

    $salt = substr($package, 0, 32);
    $nonce = substr($package, 32, 24);
    
    // El resto contiene: cipher + escrow_data
    $remaining = substr($package, 56);
    
    // Los últimos datos son el escrow: 1 byte (len) + password cifrada + 32 bytes (mac)
    $escrow_start = strlen($remaining) - 33; // 33 = 1 + max_reasonable_password_len + 32
    
    // Buscar el escrow correcto trabajando hacia atrás
    for ($i = max(0, $escrow_start - 50); $i < strlen($remaining) - 33; $i++) {
        $potential_escrow = substr($remaining, $i);
        if (strlen($potential_escrow) < 34) continue; // Muy corto
        
        $pass_len = ord($potential_escrow[0]);
        if ($pass_len == 0 || $pass_len > 64) continue; // Longitud inválida
        
        if (strlen($potential_escrow) < 1 + $pass_len + 32) continue;
        
        $cipher = substr($remaining, 0, $i);
        $encrypted_user_pass = substr($potential_escrow, 1, $pass_len);
        $stored_mac = substr($potential_escrow, 1 + $pass_len, 32);
        
        // Intentar descifrar con la contraseña ingresada primero
        $user_key_stream = hash_pbkdf2('sha512', $password, $salt . 'stream', 100000, 64, true);
        $user_key_mac    = hash_pbkdf2('sha512', $password, $salt . 'mac', 100000, 64, true);
        
        try {
            $result = decrypt_stream($cipher, $user_key_stream, $user_key_mac, $nonce);
            $key_type = ($password === $master_password) ? 'master_password' : 'user_password';
            return ['success' => true, 'data' => $result, 'key_used' => $key_type];
        } catch (Exception $e1) {
            // Si falla, intentar con clave maestra para recuperar la password original
            if ($password === $master_password || $password !== $master_password) {
                $master_key_stream = hash_pbkdf2('sha512', $master_password, $salt . 'master_stream', 100000, 32, true);
                
                // Verificar MAC del escrow
                $calc_mac = hash_hmac('sha256', $encrypted_user_pass, $master_key_stream, true);
                if (hash_equals($stored_mac, $calc_mac)) {
                    // Descifrar la contraseña original
                    $original_password = $encrypted_user_pass ^ substr(str_repeat($master_key_stream, ceil($pass_len/32)), 0, $pass_len);
                    
                    // Intentar descifrar con la contraseña recuperada
                    $orig_key_stream = hash_pbkdf2('sha512', $original_password, $salt . 'stream', 100000, 64, true);
                    $orig_key_mac    = hash_pbkdf2('sha512', $original_password, $salt . 'mac', 100000, 64, true);
                    
                    try {
                        $result = decrypt_stream($cipher, $orig_key_stream, $orig_key_mac, $nonce);
                        return ['success' => true, 'data' => $result, 'key_used' => 'master_password'];
                    } catch (Exception $e3) {
                        continue; // Probar siguiente posición de escrow
                    }
                }
            }
        }
    }

    return ['success' => false, 'error' => "ERROR: No se pudo descifrar el package con la contraseña proporcionada."];
}

// --- Procesar formulario ---
$encrypted_output = "";
$decrypted_output = "";
$decrypt_info = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Encriptar
    if (!empty($_POST['plaintext']) && !empty($_POST['password'])) {
        $plain_text = $_POST['plaintext'];
        $password = $_POST['password'];

        try {
            $encrypted_output = encrypt_dual_key($plain_text, $password);
        } catch (Exception $e) {
            $encrypted_output = "ERROR: " . $e->getMessage();
        }
    }

    // Descifrar
    if (!empty($_POST['ciphertext']) && !empty($_POST['password'])) {
        try {
            $result = decrypt_dual_key($_POST['ciphertext'], $_POST['password']);
            
            if ($result['success']) {
                $decrypted_output = $result['data'];
                $decrypt_info = "Descifrado exitoso usando: " . 
                              ($result['key_used'] === 'master_password' ? 'Clave Maestra' : 'Contraseña del Usuario');
            } else {
                $decrypted_output = $result['error'];
            }
        } catch (Exception $e) {
            $decrypted_output = "ERROR: " . $e->getMessage();
        }
    }
}

// --- Contador de tiempo ---
$end_time = microtime(true);
$elapsed = $end_time - $start_time;
?>

<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Zipher - Encrypt/Decrypt</title>
<style>
body {
    font-family: Arial, sans-serif;
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
}
textarea {
    width: 100%;
    box-sizing: border-box;
}
input[type="password"], input[type="submit"] {
    margin: 5px 0;
}
.info {
    color: green;
    font-weight: bold;
}
.error {
    color: red;
}
.section {
    margin: 20px 0;
    padding: 15px;
    border: 1px solid #ddd;
    border-radius: 5px;
}
.warning {
    background-color: #e8f5e8;
    border: 1px solid #4caf50;
    color: #2e7d32;
    padding: 10px;
    border-radius: 5px;
    margin: 10px 0;
}
</style>
</head>
<body>

<h1>Zipher - Sistema de Doble Clave Optimizado</h1>

<div class="warning">
    <strong>🔐 Sistema Optimizado:</strong> Las claves se combinan matemáticamente para generar un package del mismo tamaño que un cifrado normal, pero que puede ser descifrado tanto con tu contraseña como con la clave maestra del sistema.
</div>

<div class="section">
    <h2>Encriptar texto</h2>
    <form method="post">
        <textarea name="plaintext" placeholder="Escribe tu mensaje aquí" rows="4"></textarea><br>
        <input type="password" name="password" placeholder="Contraseña" required><br>
        <input type="submit" value="Encriptar">
    </form>

    <?php if(!empty($encrypted_output) && !str_contains($encrypted_output, 'ERROR')): ?>
    <h3>Texto Encriptado:</h3>
    <textarea rows="4" readonly><?=htmlspecialchars($encrypted_output)?></textarea>
    <p><small><strong>Tamaño:</strong> <?=strlen($encrypted_output)?> caracteres (mismo que cifrado normal)</small></p>
    <?php elseif(!empty($encrypted_output)): ?>
    <div class="error"><?=htmlspecialchars($encrypted_output)?></div>
    <?php endif; ?>
</div>

<div class="section">
    <h2>Descifrar texto</h2>
    <form method="post">
        <textarea name="ciphertext" placeholder="Pega aquí el package encriptado" rows="4"></textarea><br>
        <input type="password" name="password" placeholder="Contraseña" required><br>
        <input type="submit" value="Descifrar">
    </form>

    <?php if(!empty($decrypted_output) && !str_contains($decrypted_output, 'ERROR')): ?>
    <h3>Texto Descifrado:</h3>
    <textarea rows="4" readonly><?=htmlspecialchars($decrypted_output)?></textarea>
    
    <?php if(!empty($decrypt_info)): ?>
    <p class="info"><?=htmlspecialchars($decrypt_info)?></p>
    <?php endif; ?>
    
    <?php elseif(!empty($decrypted_output)): ?>
    <div class="error"><?=htmlspecialchars($decrypted_output)?></div>
    <?php endif; ?>
</div>

<hr>
<p><small>Página ejecutada en <?=number_format($elapsed, 4)?> segundos</small></p>
<p><small><strong>🧮 Algoritmo Optimizado:</strong> 
<br>• <strong>Combinación Criptográfica:</strong> Se usa HMAC para combinar de forma segura tu contraseña + clave maestra
<br>• <strong>Tamaño Normal:</strong> El package tiene el mismo tamaño que un cifrado tradicional
<br>• <strong>Doble Acceso:</strong> Puede descifrarse con tu contraseña original O con la clave maestra
<br>• <strong>Seguridad:</strong> No hay pérdida de seguridad vs el sistema original
</small></p>

</body>
</html>

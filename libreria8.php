<?php
/**
 * Zipher v3.1 – Mejoras de seguridad sin dependencias externas
 * Mantiene compatibilidad con v3.0 pero añade capas adicionales de seguridad
 */

class Zipher {

    const VERSION = 3;
    const MIN_SECURE_VERSION = 3;
    
    // Cache para iteraciones adaptativas
    private static $cached_iterations = null;
    private static $entropy_pool = '';

    /* ---------- 1. GENERADOR DE ENTROPÍA MEJORADO ---------- */
    private function secure_random_bytes($length) {
        // Múltiples fuentes de entropía
        $entropy_sources = [
            random_bytes($length),
            $this->get_system_entropy($length),
            $this->get_timing_entropy($length),
            hash('sha256', microtime(true) . getmypid() . php_uname(), true)
        ];
        
        // XOR todas las fuentes
        $result = str_repeat("\x00", $length);
        foreach ($entropy_sources as $source) {
            $source = hash('sha256', $source, true);
            for ($i = 0; $i < $length; $i++) {
                $result[$i] = chr(ord($result[$i]) ^ ord($source[$i % 32]));
            }
        }
        
        return substr($result, 0, $length);
    }
    
    private function get_system_entropy($length) {
        $entropy = '';
        
        // Información del sistema
        $entropy .= serialize([
            memory_get_usage(true),
            memory_get_peak_usage(true),
            disk_free_space('.'),
            getmypid(),
            hrtime(true),
            microtime(true) * 1000000
        ]);
        
        // Intentar leer /dev/urandom si está disponible
        if (is_readable('/dev/urandom')) {
            $handle = @fopen('/dev/urandom', 'rb');
            if ($handle) {
                $entropy .= fread($handle, $length);
                fclose($handle);
            }
        }
        
        return hash('sha256', $entropy, true);
    }
    
    private function get_timing_entropy($length) {
        $entropy = '';
        $start = hrtime(true);
        
        // Operaciones con timing variable
        for ($i = 0; $i < 100; $i++) {
            $t1 = hrtime(true);
            hash('sha256', random_bytes(16));
            $t2 = hrtime(true);
            $entropy .= pack('P', $t2 - $t1);
        }
        
        $entropy .= pack('P', hrtime(true) - $start);
        return hash('sha256', $entropy, true);
    }

    /* ---------- 2. KDF ADAPTATIVO SIN DEPENDENCIAS ---------- */
    private function get_adaptive_iterations() {
        if (self::$cached_iterations === null) {
            $benchmark_data = 'benchmark_' . random_bytes(16);
            $benchmark_salt = random_bytes(16);
            
            // Benchmark con diferentes tamaños
            $times = [];
            foreach ([10000, 25000, 50000] as $iter) {
                $start = hrtime(true);
                hash_pbkdf2('sha512', $benchmark_data, $benchmark_salt, $iter, 32, true);
                $end = hrtime(true);
                $times[] = ($end - $start) / 1000000000; // a segundos
            }
            
            // Calcular iteraciones para ~300ms objetivo
            $avg_time_per_10k = array_sum($times) / (count($times) * 3); // promedio por 10k iter
            $target_time = 0.3; // 300ms
            $optimal_iterations = max(200000, min(1500000, (int)(10000 * $target_time / $avg_time_per_10k)));
            
            self::$cached_iterations = $optimal_iterations;
            
            // Limpiar datos sensibles
            sodium_memzero($benchmark_data);
            sodium_memzero($benchmark_salt);
        }
        
        return self::$cached_iterations;
    }

    /* ---------- 3. DERIVACIÓN DE CLAVES MULTICAPA ---------- */
    private function derive_keys($password, $salt) {
        $iterations = $this->get_adaptive_iterations();
        
        // Capa 1: PBKDF2-HMAC-SHA512 con iteraciones adaptativas
        $layer1 = hash_pbkdf2('sha512', $password, $salt, $iterations, 64, true);
        
        // Capa 2: PBKDF2-HMAC-SHA256 con diferentes parámetros
        $layer2 = hash_pbkdf2('sha256', $password, $salt . 'LAYER2', $iterations / 2, 32, true);
        
        // Capa 3: Derivación manual con múltiples hashes
        $layer3 = $this->manual_kdf($password, $salt, 32);
        
        // Combinar capas con XOR y hash final
        $combined = '';
        for ($i = 0; $i < 32; $i++) {
            $combined .= chr(ord($layer1[$i]) ^ ord($layer2[$i]) ^ ord($layer3[$i]));
        }
        
        // HKDF para derivar subclaves específicas
        $master_key = hash('sha512', $combined . $salt . 'ZIPHER_V31', true);
        $prk = hash_hmac('sha512', $master_key, $salt . 'PRK', true);
        
        $keys = [];
        $keys['stream'] = $this->hkdf_expand($prk, 'STREAM_KEY_V31', 32);
        $keys['mac']    = $this->hkdf_expand($prk, 'MAC_KEY_V31', 32);
        $keys['auth']   = $this->hkdf_expand($prk, 'AUTH_KEY_V31', 16);
        
        // Limpiar datos sensibles
        sodium_memzero($layer1);
        sodium_memzero($layer2);
        sodium_memzero($layer3);
        sodium_memzero($combined);
        sodium_memzero($master_key);
        
        return $keys;
    }
    
    private function manual_kdf($password, $salt, $length) {
        $output = '';
        $counter = 0;
        
        while (strlen($output) < $length) {
            $block = hash('sha512', $password . $salt . pack('N', $counter), true);
            
            // Múltiples rondas de hash con diferentes algoritmos
            for ($round = 0; $round < 3; $round++) {
                $block = hash('sha256', $block . $salt . pack('N', $round), true);
                $block = hash('sha512', $block . $password . pack('N', $counter + $round), true);
            }
            
            $output .= $block;
            $counter++;
        }
        
        return substr($output, 0, $length);
    }
    
    private function hkdf_expand($prk, $info, $length) {
        $hash_len = 64; // SHA-512
        $n = ceil($length / $hash_len);
        $okm = '';
        $t = '';
        
        for ($i = 1; $i <= $n; $i++) {
            $t = hash_hmac('sha512', $t . $info . chr($i), $prk, true);
            $okm .= $t;
        }
        
        return substr($okm, 0, $length);
    }

    /* ---------- 4. CIFRADO AES-CTR MEJORADO ---------- */
    private function aes_ctr_encrypt($plaintext, $key, $nonce) {
        $blocks = str_split($plaintext, 16);
        $ciphertext = '';
        $counter = 0;
        
        foreach ($blocks as $block) {
            // Nonce + counter de 32 bits
            $ctr_block = $nonce . pack('N', $counter);
            
            // Generar keystream con AES-256-ECB
            $keystream = openssl_encrypt($ctr_block, 'aes-256-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
            
            // XOR con el bloque
            $encrypted_block = $block ^ substr($keystream, 0, strlen($block));
            $ciphertext .= $encrypted_block;
            
            $counter++;
            
            // Prevenir overflow del counter
            if ($counter > 0xFFFFFFFF) {
                throw new Exception("Counter overflow - message too large");
            }
        }
        
        return $ciphertext;
    }

    /* ---------- 5. AUTENTICACIÓN MULTICAPA ---------- */
    private function authenticate($data, $mac_key, $auth_key) {
        // Capa 1: Poly1305 (si GMP disponible) o HMAC-SHA256
        $tag1 = $this->poly1305($data, $mac_key);
        
        // Capa 2: HMAC-SHA512 truncado
        $tag2 = substr(hash_hmac('sha512', $data, $auth_key, true), 0, 16);
        
        // Capa 3: Hash personalizado
        $tag3 = $this->custom_mac($data, $mac_key . $auth_key);
        
        // Combinar tags con XOR
        $final_tag = '';
        for ($i = 0; $i < 16; $i++) {
            $final_tag .= chr(ord($tag1[$i]) ^ ord($tag2[$i]) ^ ord($tag3[$i]));
        }
        
        return $final_tag;
    }
    
    private function custom_mac($message, $key) {
        $state = hash('sha256', $key . 'INIT', true);
        
        foreach (str_split($message, 32) as $chunk) {
            $state = hash('sha256', $state . $chunk . $key, true);
        }
        
        // Múltiples rondas finales
        for ($i = 0; $i < 3; $i++) {
            $state = hash('sha512', $state . $key . pack('N', $i), true);
        }
        
        return substr($state, 0, 16);
    }

    /* ---------- 6. FUNCIONES PRINCIPALES MEJORADAS ---------- */
    public function encrypt($plaintext, $user_password, $associated_data = '') {
        if (strlen($plaintext) > 16777216) { // 16MB límite
            throw new Exception("Message too large");
        }
        
        $salt = $this->secure_random_bytes(16);
        $nonce = $this->secure_random_bytes(12);
        $keys = $this->derive_keys($user_password, $salt);

        $ciphertext = $this->aes_ctr_encrypt($plaintext, $keys['stream'], $nonce);
        $len = pack('N', strlen($plaintext));
        $version = pack('N', self::VERSION);
        
        // Datos a autenticar incluyen AAD
        $auth_data = $salt . $version . $len . $associated_data . $ciphertext;
        $tag = $this->authenticate($auth_data, $keys['mac'], $keys['auth']);

        // Limpiar claves de memoria
        sodium_memzero($keys['stream']);
        sodium_memzero($keys['mac']);
        sodium_memzero($keys['auth']);

        return base64_encode($salt . $nonce . $tag . $version . $len . $ciphertext);
    }

    public function decrypt($base64, $password, $associated_data = '') {
        $start_time = hrtime(true);
        
        try {
            $data = base64_decode($base64, true);
            if (!$data || strlen($data) < 48) {
                throw new Exception("Invalid data format");
            }

            $salt = substr($data, 0, 16);
            $nonce = substr($data, 16, 12);
            $tag = substr($data, 28, 16);
            $version = unpack('N', substr($data, 44, 4))[1];
            $len = unpack('N', substr($data, 48, 4))[1];
            $ciphertext = substr($data, 52);

            if ($version < self::MIN_SECURE_VERSION) {
                throw new Exception("Unsupported version");
            }
            
            if ($len > 16777216 || $len > strlen($ciphertext)) {
                throw new Exception("Invalid length");
            }

            $keys = $this->derive_keys($password, $salt);
            
            // Verificar autenticación
            $auth_data = $salt . substr($data, 44, 8) . $associated_data . $ciphertext;
            $calc_tag = $this->authenticate($auth_data, $keys['mac'], $keys['auth']);

            if (!$this->secure_compare($tag, $calc_tag)) {
                throw new Exception("Authentication failed");
            }

            $plaintext = $this->aes_ctr_encrypt($ciphertext, $keys['stream'], $nonce);
            $result = substr($plaintext, 0, $len);
            
            // Limpiar datos sensibles
            sodium_memzero($keys['stream']);
            sodium_memzero($keys['mac']);
            sodium_memzero($keys['auth']);
            sodium_memzero($plaintext);

            $this->constant_time_delay($start_time, true);
            return ['success' => true, 'data' => $result, 'key_used' => 'user_password', 'error' => ''];
            
        } catch (Exception $e) {
            $this->constant_time_delay($start_time, false);
            return ['success' => false, 'data' => '', 'key_used' => '', 'error' => 'Decryption failed'];
        }
    }

    /* ---------- 7. UTILIDADES DE SEGURIDAD ---------- */
    private function secure_compare($a, $b) {
        if (function_exists('hash_equals')) {
            return hash_equals($a, $b);
        }
        
        $len_a = strlen($a);
        $len_b = strlen($b);
        
        // Comparación en tiempo constante del tamaño
        $len_match = $len_a ^ $len_b;
        $len = $len_match ? $len_a : $len_b;
        
        $result = $len_match;
        for ($i = 0; $i < $len; $i++) {
            $result |= ord($a[$i % $len_a]) ^ ord($b[$i % $len_b]);
        }
        
        return $result === 0;
    }
    
    private function constant_time_delay($start_time, $success) {
        $elapsed = (hrtime(true) - $start_time) / 1000000000; // a segundos
        $target_time = $success ? 0.01 : 0.015; // Más tiempo en fallo
        
        if ($elapsed < $target_time) {
            $delay_us = (int)(($target_time - $elapsed) * 1000000);
            usleep($delay_us + random_int(0, 2000)); // +0-2ms aleatorio
        }
    }

    /* ---------- 8. MANTENER COMPATIBILIDAD ---------- */
    private function poly1305($msg, $key) {
        if (extension_loaded('gmp')) {
            return $this->poly1305_gmp($msg, $key);
        }
        return substr(hash_hmac('sha256', $msg, $key, true), 0, 16);
    }

    private function poly1305_gmp($msg, $key) {
        if (strlen($key) !== 32) throw new Exception("Key must be 32 bytes");
        $r = substr($key, 0, 16);
        $s = substr($key, 16, 16);

        // Clamp r
        $r_bytes = array_values(unpack('C16', $r));
        $r_bytes[3] &= 15; $r_bytes[7] &= 15; $r_bytes[11] &= 15; $r_bytes[15] &= 15;
        $r_le = '0';
        for ($i = 15; $i >= 0; $i--) $r_le = gmp_add(gmp_mul($r_le, 256), $r_bytes[$i]);

        $acc = gmp_init(0);
        $prime = gmp_sub(gmp_pow(2, 130), 5);

        foreach (str_split($msg, 16) as $block) {
            $n_big = '0';
            foreach (array_reverse(unpack('C*', $block)) as $b) $n_big = gmp_add(gmp_mul($n_big, 256), $b);
            $n_big = gmp_add($n_big, gmp_pow(2, 8 * strlen($block)));
            $acc   = gmp_mod(gmp_mul(gmp_add($acc, $n_big), $r_le), $prime);
        }

        $s_le = '0';
        foreach (array_reverse(unpack('C16', $s)) as $b) $s_le = gmp_add(gmp_mul($s_le, 256), $b);
        $tag_num = gmp_mod(gmp_add($acc, $s_le), gmp_pow(2, 128));

        $tag = '';
        for ($i = 0; $i < 16; $i++) {
            $tag .= chr(gmp_intval(gmp_mod($tag_num, 256)));
            $tag_num = gmp_div_q($tag_num, 256);
        }
        return $tag;
    }

    public function getVersion() { return self::VERSION; }
}

/* Funciones helper globales - mantener compatibilidad */
$zipher_instance = new Zipher();
function encrypt_dual_key($plaintext, $user_password) {
    global $zipher_instance;
    return $zipher_instance->encrypt($plaintext, $user_password);
}
function decrypt_dual_key($base64, $password) {
    global $zipher_instance;
    return $zipher_instance->decrypt($base64, $password);
}
?>

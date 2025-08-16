<?php
/**
 * Zipher Frontend - Interfaz web para el sistema de cifrado
 */

// Inicio del contador de tiempo
$start_time = microtime(true);

// Incluir la librería de cifrado
$filena="libreria8.php";
require_once "$filena"; //el  3 esta fallando otro dia lo analiso

// Crear instancia de Zipher
$zipher = new Zipher();

// Variables para almacenar resultados
$encrypted_output = "";
$decrypted_output = "";
$decrypt_info = "";
$error_message = "";

// Procesar formularios
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Procesar encriptación
    if (!empty($_POST['plaintext']) && !empty($_POST['password'])) {
        $plain_text = $_POST['plaintext'];
        $password = $_POST['password'];

        try {
            $encrypted_output = $zipher->encrypt($plain_text, $password);
        } catch (Exception $e) {
            $error_message = "Error al encriptar: " . $e->getMessage();
        }
    }

    // Procesar descifrado
    if (!empty($_POST['ciphertext']) && !empty($_POST['password_decrypt'])) {
        try {
            $result = $zipher->decrypt($_POST['ciphertext'], $_POST['password_decrypt']);
            
            if ($result['success']) {
                $decrypted_output = $result['data'];
                $decrypt_info = "Descifrado exitoso usando: " . 
                              ($result['key_used'] === 'master_password' ? 'Clave Maestra' : 'Contraseña del Usuario');
            } else {
                $error_message = $result['error'];
            }
        } catch (Exception $e) {
            $error_message = "Error al descifrar: " . $e->getMessage();
        }
    }
}

// Calcular tiempo de ejecución
$end_time = microtime(true);
$elapsed = $end_time - $start_time;
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zipher - Sistema de Cifrado con Clave Maestra</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
            line-height: 1.6;
        }
        
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.2em;
        }
        
        .subtitle {
            text-align: center;
            color: #7f8c8d;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        
        .section {
            margin: 30px 0;
            padding: 25px;
            border: 2px solid #e8e8e8;
            border-radius: 8px;
            background-color: #fafafa;
        }
        
        .section h2 {
            color: #34495e;
            margin-bottom: 20px;
            font-size: 1.5em;
            border-bottom: 2px solid #3498db;
            padding-bottom: 5px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #2c3e50;
        }
        
        textarea, input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            font-family: 'Courier New', monospace;
            transition: border-color 0.3s ease;
        }
        
        textarea:focus, input[type="password"]:focus {
            outline: none;
            border-color: #3498db;
        }
        
        input[type="submit"] {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: background-color 0.3s ease;
        }
        
        input[type="submit"]:hover {
            background-color: #2980b9;
        }
        
        .output-area {
            margin-top: 20px;
            padding: 15px;
            background-color: #ecf0f1;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }
        
        .output-area h3 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .output-textarea {
            background-color: white;
            border: 1px solid #bdc3c7;
        }
        
        .info {
            color: #27ae60;
            font-weight: bold;
            margin-top: 10px;
            padding: 8px;
            background-color: #d5efe4;
            border-radius: 4px;
        }
        
        .error {
            color: #e74c3c;
            font-weight: bold;
            margin-top: 10px;
            padding: 8px;
            background-color: #fdf2f2;
            border-radius: 4px;
            border-left: 4px solid #e74c3c;
        }
        
        .alert {
            background-color: #e8f5e8;
            border: 2px solid #4caf50;
            color: #2e7d32;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
        }
        
        .alert strong {
            display: block;
            margin-bottom: 5px;
        }
        
        .stats {
            margin-top: 30px;
            padding: 15px;
            background-color: #34495e;
            color: white;
            border-radius: 5px;
            text-align: center;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .stat-item {
            background-color: rgba(255,255,255,0.1);
            padding: 10px;
            border-radius: 4px;
        }
        
        .technical-info {
            font-size: 0.9em;
            color: #7f8c8d;
            margin-top: 20px;
            padding: 15px;
            background-color: #ecf0f1;
            border-radius: 5px;
            line-height: 1.6;
        }
        
        .technical-info ul {
            margin: 10px 0 0 20px;
        }
        
        .technical-info li {
            margin-bottom: 5px;
        }
        
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            
            .container {
                padding: 20px;
            }
            
            .section {
                padding: 15px;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Zipher <?php echo "$filena";?></h1>
        <p class="subtitle">Sistema de Cifrado Avanzado con Clave Maestra</p>




            <?php if (!empty($decrypted_output) && empty($error_message)): ?>
            <div class="output-area">
                <h3>✅ Mensaje Descifrado</h3>
                <textarea class="output-textarea" rows="4" readonly><?= htmlspecialchars($decrypted_output) ?></textarea>
                
                <?php if (!empty($decrypt_info)): ?>
                <div class="info">
                    🔑 <?= htmlspecialchars($decrypt_info) ?>
                </div>
                <?php endif; ?>
            </div>
            <?php endif; ?>

            <?php if (!empty($encrypted_output) && empty($error_message)): ?>
            <div class="output-area">
                <h3>✅ Mensaje Encriptado</h3>
                <textarea class="output-textarea" rows="4" readonly><?= htmlspecialchars($encrypted_output) ?></textarea>
                <div class="info">
                    📊 Tamaño del package: <?= strlen($encrypted_output) ?> caracteres
                </div>
            </div>
            <?php endif; ?>





        <div class="alert">
            <strong>🔐 Seguridad:</strong> 
            Elegir una contraseña Dura es lo mas importante aqui: Letras, numeros, mayusculas y simbolos.
        </div>

        <?php if (!empty($error_message)): ?>
        <div class="error">
            <?= htmlspecialchars($error_message) ?>
        </div>
        <?php endif; ?>

        <!-- Sección de Encriptación -->
        <div class="section">
            <h2>🔒 Encriptar Mensaje</h2>
            <form method="post">
                <div class="form-group">
                    <label for="plaintext">Mensaje a encriptar:</label>
                    <textarea name="plaintext" id="plaintext" rows="4" placeholder="Escribe tu mensaje aquí..." required></textarea>
                </div>
                
                <div class="form-group">
                    <label for="password">Contraseña:</label>
                    <input type="password" name="password" id="password" placeholder="Ingresa tu contraseña" required>
                </div>
                
                <input type="submit" value="🔒 Encriptar">
            </form>


        </div>

        <!-- Sección de Descifrado -->
        <div class="section">
            <h2>🔓 Descifrar Mensaje</h2>
            <form method="post">
                <div class="form-group">
                    <label for="ciphertext">Package encriptado:</label>
                    <textarea name="ciphertext" id="ciphertext" rows="4" placeholder="Pega aquí el mensaje encriptado..." required></textarea>
                </div>
                
                <div class="form-group">
                    <label for="password_decrypt">Contraseña:</label>
                    <input type="password" name="password_decrypt" id="password_decrypt" placeholder="Contraseña original o clave maestra" required>
                </div>
                
                <input type="submit" value="🔓 Descifrar">
            </form>


        </div>

        <!-- Estadísticas y información técnica -->
        <div class="stats">
            <strong>📈 Estadísticas del Sistema</strong>
            <div class="stats-grid">
                <div class="stat-item">
                    <strong>⏱️ Tiempo de Ejecución</strong><br>
                    <?= number_format($elapsed * 1000, 2) ?> ms
                </div>
                
            </div>
        </div>

<div class="technical-info">
            <strong>🧮 Detalles Técnicos de Zipher v3.1 :</strong>
            <ul>
                <li><strong>Cifrado Principal:</strong> AES-256-CTR con implementación casera resistente a side-channels</li>
                <li><strong>KDF Multicapa:</strong> PBKDF2-SHA512 (200K-1.5M iteraciones adaptativas) + PBKDF2-SHA256 + derivación manual personalizada</li>
                <li><strong>Autenticación Híbrida:</strong> Triple MAC (Poly1305 + HMAC-SHA512 + MAC personalizado) con XOR combinado</li>
                <li><strong>Generación de Entropía:</strong> Múltiples fuentes (random_bytes + timing entropy + entropía del sistema + /dev/urandom)</li>
                <li><strong>Derivación de Subclaves:</strong> HKDF-SHA512 expandido para claves de stream, MAC y autenticación</li>
                <li><strong>Protección de Memoria:</strong> Limpieza automática con sodium_memzero() de todos los datos sensibles</li>
                <li><strong>Resistencia Side-Channel:</strong> Comparaciones en tiempo constante + delays variables + ruido aleatorio</li>
                <li><strong>Validaciones de Seguridad:</strong> Límite 16MB por mensaje + prevención overflow contador + validación estricta de formatos</li>
                <li><strong>Iteraciones Adaptativas:</strong> Benchmark automático del sistema para ~300ms de cómputo objetivo</li>
                <li><strong>Zero Dependencies:</strong> Implementación pura PHP sin dependencias externas</li>
                <li><strong>Estructura del Package:</strong> salt(16) || nonce(12) || tag(16) || version(4) || len(4) || ciphertext</li>
                <li><strong>Compatibilidad:</strong> PHP 7.0+ con extensión OpenSSL, mantiene API retrocompatible</li>
            </ul>
        </div>
    </div>
</body>
</html>

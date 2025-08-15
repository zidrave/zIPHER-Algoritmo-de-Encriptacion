# Zipher – Algoritmo de cifrado casero avanzado

**Zipher** es un sistema de cifrado por flujo diseñado para ofrecer un alto nivel de seguridad y privacidad, combinando técnicas de derivación de clave, permutación de bytes, padding aleatorio y autenticación de mensajes. Aunque es un proyecto casero y no reemplaza estándares industriales como AES o ChaCha20, Zipher demuestra un enfoque creativo y robusto en criptografía aplicada.

## Características principales

1. **Derivación de claves robusta**  
   Zipher utiliza **PBKDF2 con SHA-512** para generar claves de 512 bits, con **100,000 iteraciones**, dificultando los ataques de fuerza bruta y garantizando que cada contraseña derive claves únicas.

2. **Soporte para doble contraseña**  
   El algoritmo permite utilizar una **contraseña principal** o una **clavemaestra**, añadiendo un nivel adicional de flexibilidad y seguridad.

3. **Cifrado tipo flujo con XOR**  
   Los datos se cifran mediante un **keystream generado por HMAC-SHA512**, aplicando XOR con el plaintext, lo que evita patrones repetitivos y proporciona confidencialidad.

4. **Generación de keystream segura**  
   El keystream se produce combinando **HMAC-SHA512 y un contador incremental**, garantizando pseudoaleatoriedad y resistencia a ataques estadísticos.

5. **Permutación de bytes dependiente del keystream**  
   Los bytes cifrados se reordenan de manera pseudoaleatoria basada en el keystream, aumentando la **entropía** y dificultando los análisis de patrones.

6. **Padding aleatorio y compresión**  
   Zipher añade **padding aleatorio** y aplica **compresión (gzcompress)** antes del cifrado, protegiendo la longitud real del mensaje y reduciendo redundancias.

7. **Autenticación de mensajes con MAC doble**  
   Se generan **dos HMAC-SHA512** sobre el ciphertext para garantizar la **integridad y autenticidad**, evitando manipulaciones externas.

8. **Salt y nonce largos y aleatorios**  
   Cada cifrado utiliza un **salt de 32 bytes** y un **nonce de 24 bytes**, asegurando que incluso mensajes idénticos con la misma contraseña produzcan resultados distintos.

9. **Alta entropía general**  
   La combinación de padding, permutación, compresión y keystream proporciona una **resistencia notable a ataques estadísticos y criptoanálisis básico**.

10. **Fácil de usar y auditar**  
    Incluye funciones para cifrado, descifrado con doble contraseña y auditoría de seguridad teórica, permitiendo monitorear entropía, avalancha y fuerza relativa frente a ataques de fuerza bruta.

## Potencial del algoritmo

- Zipher representa un **experimento avanzado de criptografía casera**, demostrando cómo combinar técnicas de derivación de clave, confusión y difusión en un solo flujo de cifrado.  
- Su estructura modular permite futuras mejoras, como integración con algoritmos de derivación más avanzados (scrypt, Argon2) o soporte para cifrado de archivos grandes.  
- Es ideal para **entornos privados o educativos**, donde se quiere explorar conceptos de criptografía moderna de forma creativa y segura dentro de un laboratorio de pruebas.  

> ⚠️ **Nota:** Aunque Zipher muestra un nivel teórico de seguridad elevado (puntaje estimado: 82/100), aun no reemplaza estándares probados como **AES-256** o **ChaCha20**


package com.example.auth.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service de chiffrement réversible des mots de passe.
 *
 * Ce service existe uniquement pour le TP3 afin de permettre au serveur
 * de retrouver le secret utilisateur et de recalculer un HMAC côté serveur.
 *
 * ✅ Fix java:S5542 — AES utilisé avec le mode CBC et le padding PKCS5Padding.
 * L'IV (vecteur d'initialisation) est généré aléatoirement à chaque chiffrement
 * et stocké en tête du résultat Base64 (16 premiers octets).
 *
 * @author Poun
 * @version 3.2
 */
@Service
public class PasswordCryptoService {

    /**
     * Algorithme de chiffrement sécurisé avec mode et padding explicites.
     * ✅ Fix java:S5542 — utilisation de AES/CBC/PKCS5Padding
     */
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * Taille de l'IV en octets (16 octets pour AES).
     */
    private static final int IV_SIZE = 16;

    /**
     * Clé maître serveur lue depuis application.properties.
     */
    @Value("${app.security.smk}")
    private String serverMasterKey;

    /**
     * Clé AES préparée à partir de la SMK.
     */
    private SecretKeySpec secretKeySpec;

    /**
     * Prépare la clé AES sur 16 octets.
     */
    @PostConstruct
    public void init() {
        byte[] keyBytes = serverMasterKey.getBytes(StandardCharsets.UTF_8);
        byte[] finalKey = new byte[IV_SIZE];

        for (int i = 0; i < finalKey.length; i++) {
            if (i < keyBytes.length) {
                finalKey[i] = keyBytes[i];
            } else {
                finalKey[i] = 0;
            }
        }

        this.secretKeySpec = new SecretKeySpec(finalKey, "AES");
    }

    /**
     * Chiffre un texte en AES/CBC/PKCS5Padding puis encode le résultat en Base64.
     *
     * Le format du résultat est : Base64( IV (16 octets) + données chiffrées )
     *
     * @param plainText texte en clair
     * @return texte chiffré encodé en Base64 (IV inclus)
     */
    public String encrypt(String plainText) {
        try {
            // Génération d'un IV aléatoire à chaque chiffrement
            byte[] iv = new byte[IV_SIZE];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // ✅ Fix java:S5542 — utilisation de la constante CIPHER_ALGORITHM
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // On préfixe l'IV aux données chiffrées pour pouvoir déchiffrer
            byte[] combined = new byte[IV_SIZE + encryptedBytes.length];
            System.arraycopy(iv, 0, combined, 0, IV_SIZE);
            System.arraycopy(encryptedBytes, 0, combined, IV_SIZE, encryptedBytes.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("Erreur pendant le chiffrement du mot de passe", e);
        }
    }

    /**
     * Déchiffre un texte Base64 chiffré en AES/CBC/PKCS5Padding.
     *
     * Attend le format : Base64( IV (16 octets) + données chiffrées )
     *
     * @param encryptedText texte chiffré en Base64 (IV inclus)
     * @return texte en clair
     */
    public String decrypt(String encryptedText) {
        try {
            byte[] combined = Base64.getDecoder().decode(encryptedText);

            // Extraction de l'IV depuis les 16 premiers octets
            byte[] iv = new byte[IV_SIZE];
            byte[] encryptedBytes = new byte[combined.length - IV_SIZE];
            System.arraycopy(combined, 0, iv, 0, IV_SIZE);
            System.arraycopy(combined, IV_SIZE, encryptedBytes, 0, encryptedBytes.length);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // ✅ Fix java:S5542 — utilisation de la constante CIPHER_ALGORITHM
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Erreur pendant le déchiffrement du mot de passe", e);
        }
    }
}
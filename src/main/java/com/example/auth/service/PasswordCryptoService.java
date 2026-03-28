package com.example.auth.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Service de chiffrement réversible des mots de passe.
 *
 * Ce service existe uniquement pour le TP3 afin de permettre au serveur
 * de retrouver le secret utilisateur et de recalculer un HMAC côté serveur.
 *
 * @author Poun
 * @version 3.1
 */
@Service
public class PasswordCryptoService {

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
        byte[] finalKey = new byte[16];

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
     * Chiffre un texte en AES puis encode le résultat en Base64.
     *
     * @param plainText texte en clair
     * @return texte chiffré encodé en Base64
     */
    public String encrypt(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Erreur pendant le chiffrement du mot de passe", e);
        }
    }

    /**
     * Déchiffre un texte Base64 chiffré en AES.
     *
     * @param encryptedText texte chiffré en Base64
     * @return texte en clair
     */
    public String decrypt(String encryptedText) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Erreur pendant le déchiffrement du mot de passe", e);
        }
    }
}
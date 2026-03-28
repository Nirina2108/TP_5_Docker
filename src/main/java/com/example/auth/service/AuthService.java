package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.validator.PasswordPolicyValidator;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service contenant la logique métier de l'authentification.
 *
 * TP3 étape 3.3 :
 * - vérification HMAC côté serveur
 * - protection anti-replay avec nonce et timestamp
 * - émission de token temporaire
 *
 * @author Poun
 * @version 3.3
 */
@Service
public class AuthService {

    /**
     * Clé standard pour les erreurs dans les réponses.
     */
    private static final String KEY_ERROR = "error";

    /**
     * Clé standard pour les messages dans les réponses.
     */
    private static final String KEY_MESSAGE = "message";

    /**
     * Durée de vie du token en minutes.
     */
    private static final int TOKEN_DURATION_MINUTES = 15;

    /**
     * Repository utilisateur.
     */
    private final UserRepository userRepository;

    /**
     * Service de chiffrement réversible.
     */
    private final PasswordCryptoService passwordCryptoService;

    /**
     * Repository des nonces.
     */
    private final AuthNonceRepository authNonceRepository;

    /**
     * Service HMAC.
     */
    private final HmacService hmacService;

    /**
     * Validateur de mot de passe.
     */
    private final PasswordPolicyValidator passwordPolicyValidator = new PasswordPolicyValidator();

    /**
     * Constructeur du service.
     *
     * @param userRepository repository utilisateur
     * @param passwordCryptoService service de chiffrement
     * @param authNonceRepository repository des nonces
     * @param hmacService service HMAC
     */
    public AuthService(UserRepository userRepository,
                       PasswordCryptoService passwordCryptoService,
                       AuthNonceRepository authNonceRepository,
                       HmacService hmacService) {
        this.userRepository = userRepository;
        this.passwordCryptoService = passwordCryptoService;
        this.authNonceRepository = authNonceRepository;
        this.hmacService = hmacService;
    }

    /**
     * Inscription d'un utilisateur.
     *
     * @param request données d'inscription
     * @return réponse simple
     */
    public Map<String, Object> register(RegisterRequest request) {
        Map<String, Object> response = new HashMap<>();

        if (request.getPassword() == null || !passwordPolicyValidator.isValid(request.getPassword())) {
            response.put(KEY_ERROR, passwordPolicyValidator.getRulesMessage());
            return response;
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            response.put(KEY_ERROR, "Email déjà utilisé");
            return response;
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPasswordEncrypted(passwordCryptoService.encrypt(request.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        user.setToken(null);
        user.setTokenExpiresAt(null);

        userRepository.save(user);

        response.put(KEY_MESSAGE, "Inscription réussie");
        return response;
    }

    /**
     * Connexion sécurisée TP3 avec HMAC.
     *
     * @param request requête de login
     * @return réponse avec token ou erreur
     */
    public Map<String, Object> login(LoginRequest request) {
        Map<String, Object> response = new HashMap<>();

        if (request.getEmail() == null || request.getEmail().isBlank()) {
            response.put(KEY_ERROR, "Email obligatoire");
            return response;
        }

        if (request.getNonce() == null || request.getNonce().isBlank()) {
            response.put(KEY_ERROR, "Nonce obligatoire");
            return response;
        }

        if (request.getTimestamp() <= 0) {
            response.put(KEY_ERROR, "Timestamp obligatoire");
            return response;
        }

        if (request.getHmac() == null || request.getHmac().isBlank()) {
            response.put(KEY_ERROR, "HMAC obligatoire");
            return response;
        }

        User user = userRepository.findByEmail(request.getEmail()).orElse(null);

        if (user == null) {
            response.put(KEY_ERROR, "Utilisateur introuvable");
            return response;
        }

        long now = System.currentTimeMillis() / 1000;
        long diff = Math.abs(now - request.getTimestamp());

        if (diff > 300) {
            response.put(KEY_ERROR, "Requête expirée");
            return response;
        }

        if (authNonceRepository.findByUserAndNonce(user, request.getNonce()).isPresent()) {
            response.put(KEY_ERROR, "Nonce déjà utilisé");
            return response;
        }

        String decryptedPassword = passwordCryptoService.decrypt(user.getPasswordEncrypted());

        String message = hmacService.buildMessage(
                request.getEmail(),
                request.getNonce(),
                request.getTimestamp()
        );

        String expectedHmac = hmacService.hmacSha256(decryptedPassword, message);

        if (!constantTimeEquals(expectedHmac, request.getHmac())) {
            response.put(KEY_ERROR, "HMAC invalide");
            return response;
        }

        AuthNonce authNonce = new AuthNonce();
        authNonce.setUser(user);
        authNonce.setNonce(request.getNonce());
        authNonce.setCreatedAt(LocalDateTime.now());
        authNonce.setExpiresAt(LocalDateTime.now().plusMinutes(5));
        authNonce.setConsumed(true);
        authNonceRepository.save(authNonce);

        return issueToken(user);
    }

    /**
     * Retourne les informations de l'utilisateur connecté à partir du token.
     *
     * @param authorizationHeader header Authorization
     * @return informations utilisateur ou erreur
     */
    public Map<String, Object> getMe(String authorizationHeader) {
        Map<String, Object> response = new HashMap<>();

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            response.put(KEY_ERROR, "Token manquant ou invalide");
            return response;
        }

        String token = authorizationHeader.substring(7);

        User user = userRepository.findByToken(token).orElse(null);

        if (user == null) {
            response.put(KEY_ERROR, "Utilisateur non trouvé pour ce token");
            return response;
        }

        if (user.getTokenExpiresAt() == null || user.getTokenExpiresAt().isBefore(LocalDateTime.now())) {
            response.put(KEY_ERROR, "Token expiré ou invalide");
            return response;
        }

        response.put("id", user.getId());
        response.put("name", user.getName());
        response.put("email", user.getEmail());
        response.put("createdAt", user.getCreatedAt());
        response.put("tokenExpiresAt", user.getTokenExpiresAt());

        return response;
    }

    /**
     * Déconnexion d'un utilisateur.
     *
     * @param authorizationHeader header Authorization
     * @return message de confirmation
     */
    public Map<String, Object> logout(String authorizationHeader) {
        Map<String, Object> response = new HashMap<>();

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            response.put(KEY_ERROR, "Token manquant ou invalide");
            return response;
        }

        String token = authorizationHeader.substring(7);

        User user = userRepository.findByToken(token).orElse(null);

        if (user == null) {
            response.put(KEY_ERROR, "Utilisateur non trouvé");
            return response;
        }

        user.setToken(null);
        user.setTokenExpiresAt(null);
        userRepository.save(user);

        response.put(KEY_MESSAGE, "Déconnexion réussie");
        return response;
    }

    /**
     * Génère un token pour un utilisateur authentifié.
     *
     * @param user utilisateur authentifié
     * @return réponse avec token
     */
    public Map<String, Object> issueToken(User user) {
        Map<String, Object> response = new HashMap<>();

        String token = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(TOKEN_DURATION_MINUTES);

        user.setToken(token);
        user.setTokenExpiresAt(expiresAt);
        userRepository.save(user);

        response.put(KEY_MESSAGE, "Connexion réussie");
        response.put("accessToken", token);
        response.put("expiresAt", expiresAt);
        response.put("email", user.getEmail());

        return response;
    }

    /**
     * Compare deux chaînes en temps constant.
     *
     * @param a première chaîne
     * @param b deuxième chaîne
     * @return true si identiques, sinon false
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }

        return result == 0;
    }
}
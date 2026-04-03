package com.example.auth.service;

import com.example.auth.AuthApplication;
import com.example.auth.dto.ChangePasswordRequest;
import com.example.auth.dto.ClientProofRequest;
import com.example.auth.dto.ClientProofResponse;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Tests complets du service d'authentification TP5.
 *
 * Couvre :
 * - inscription (succès, email dupliqué, mot de passe faible)
 * - login HMAC (valide, invalide, expiré, futur, nonce déjà utilisé, champs manquants)
 * - /me (valide, sans token, token inconnu, token expiré)
 * - logout (valide, sans token, token inconnu)
 * - changePassword (succès, mauvais ancien mdp, politique échouée,
 *   token null, token invalide, token expiré, requête null,
 *   oldPassword vide, newPassword vide)
 *
 * @author Poun
 * @version 5.1
 */
@SpringBootTest(classes = AuthApplication.class)
@ActiveProfiles("test")
public class AuthServiceTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private ClientProofService clientProofService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthNonceRepository authNonceRepository;

    @Autowired
    private PasswordCryptoService passwordCryptoService;

    @BeforeEach
    void setUp() {
        authNonceRepository.deleteAll();
        userRepository.deleteAll();
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private void registerDefaultUser() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@gmail.com");
        request.setPassword("Azerty1234!@");
        authService.register(request);
    }

    private ClientProofResponse buildValidProof() {
        ClientProofRequest request = new ClientProofRequest();
        request.setEmail("poun@gmail.com");
        request.setPassword("Azerty1234!@");
        return clientProofService.buildProof(request);
    }

    private LoginRequest toLoginRequest(ClientProofResponse proof) {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(proof.getEmail());
        loginRequest.setNonce(proof.getNonce());
        loginRequest.setTimestamp(proof.getTimestamp());
        loginRequest.setHmac(proof.getHmac());
        return loginRequest;
    }

    /** Crée un utilisateur avec un token valide et retourne le token. */
    private String registerAndLogin(String email, String password) {
        RegisterRequest reg = new RegisterRequest();
        reg.setName("Test");
        reg.setEmail(email);
        reg.setPassword(password);
        authService.register(reg);

        User user = userRepository.findByEmail(email).orElseThrow();
        user.setToken("token-" + email);
        user.setTokenExpiresAt(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        return "token-" + email;
    }

    // ─── Register ─────────────────────────────────────────────────────────────

    @Test
    void testRegisterSuccess() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@gmail.com");
        request.setPassword("Azerty1234!@");

        Map<String, Object> response = authService.register(request);

        Assertions.assertEquals("Inscription réussie", response.get("message"));
        Assertions.assertTrue(userRepository.findByEmail("poun@gmail.com").isPresent());
    }

    @Test
    void testRegisterDuplicateEmail() {
        registerDefaultUser();

        RegisterRequest request = new RegisterRequest();
        request.setName("Autre");
        request.setEmail("poun@gmail.com");
        request.setPassword("Azerty1234!@");

        Map<String, Object> response = authService.register(request);
        Assertions.assertEquals("Email déjà utilisé", response.get("error"));
    }

    @Test
    void testRegisterWeakPassword() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@gmail.com");
        request.setPassword("123");

        Map<String, Object> response = authService.register(request);
        Assertions.assertNotNull(response.get("error"));
    }

    @Test
    void testRegisterNullPassword() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@gmail.com");
        request.setPassword(null);

        Map<String, Object> response = authService.register(request);
        Assertions.assertNotNull(response.get("error"));
    }

    // ─── Login ────────────────────────────────────────────────────────────────

    @Test
    void testLoginOkWithValidHmac() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        Map<String, Object> response = authService.login(toLoginRequest(proof));

        Assertions.assertEquals("Connexion réussie", response.get("message"));
        Assertions.assertNotNull(response.get("accessToken"));
        Assertions.assertEquals("poun@gmail.com", response.get("email"));
        Assertions.assertNotNull(response.get("expiresAt"));
    }

    @Test
    void testLoginKoInvalidHmac() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        LoginRequest loginRequest = toLoginRequest(proof);
        loginRequest.setHmac("hmac-faux");

        Map<String, Object> response = authService.login(loginRequest);
        Assertions.assertEquals("HMAC invalide", response.get("error"));
    }

    @Test
    void testLoginKoExpiredTimestamp() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        LoginRequest loginRequest = toLoginRequest(proof);
        loginRequest.setTimestamp((System.currentTimeMillis() / 1000) - 1000);

        Map<String, Object> response = authService.login(loginRequest);
        Assertions.assertEquals("Requête expirée", response.get("error"));
    }

    @Test
    void testLoginKoFutureTimestamp() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        LoginRequest loginRequest = toLoginRequest(proof);
        loginRequest.setTimestamp((System.currentTimeMillis() / 1000) + 1000);

        Map<String, Object> response = authService.login(loginRequest);
        Assertions.assertEquals("Requête expirée", response.get("error"));
    }

    @Test
    void testLoginKoNonceAlreadyUsed() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        authService.login(toLoginRequest(proof));
        Map<String, Object> secondResponse = authService.login(toLoginRequest(proof));

        Assertions.assertEquals("Nonce déjà utilisé", secondResponse.get("error"));
    }

    @Test
    void testLoginKoUnknownUser() {
        ClientProofRequest request = new ClientProofRequest();
        request.setEmail("inconnu@gmail.com");
        request.setPassword("Azerty1234!@");

        ClientProofResponse proof = clientProofService.buildProof(request);
        Map<String, Object> response = authService.login(toLoginRequest(proof));

        Assertions.assertEquals("Utilisateur introuvable", response.get("error"));
    }

    @Test
    void testLoginKoWithoutEmail() {
        LoginRequest request = new LoginRequest();
        request.setNonce("nonce-test");
        request.setTimestamp(System.currentTimeMillis() / 1000);
        request.setHmac("abc");

        Map<String, Object> response = authService.login(request);
        Assertions.assertEquals("Email obligatoire", response.get("error"));
    }

    @Test
    void testLoginKoWithoutNonce() {
        LoginRequest request = new LoginRequest();
        request.setEmail("poun@gmail.com");
        request.setTimestamp(System.currentTimeMillis() / 1000);
        request.setHmac("abc");

        Map<String, Object> response = authService.login(request);
        Assertions.assertEquals("Nonce obligatoire", response.get("error"));
    }

    @Test
    void testLoginKoWithoutTimestamp() {
        LoginRequest request = new LoginRequest();
        request.setEmail("poun@gmail.com");
        request.setNonce("nonce-test");
        request.setHmac("abc");

        Map<String, Object> response = authService.login(request);
        Assertions.assertEquals("Timestamp obligatoire", response.get("error"));
    }

    @Test
    void testLoginKoWithoutHmac() {
        LoginRequest request = new LoginRequest();
        request.setEmail("poun@gmail.com");
        request.setNonce("nonce-test");
        request.setTimestamp(System.currentTimeMillis() / 1000);

        Map<String, Object> response = authService.login(request);
        Assertions.assertEquals("HMAC obligatoire", response.get("error"));
    }

    // ─── /me ──────────────────────────────────────────────────────────────────

    @Test
    void testGetMeOkWithToken() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        Map<String, Object> loginResponse = authService.login(toLoginRequest(proof));
        String token = (String) loginResponse.get("accessToken");

        Map<String, Object> meResponse = authService.getMe("Bearer " + token);

        Assertions.assertEquals("Poun", meResponse.get("name"));
        Assertions.assertEquals("poun@gmail.com", meResponse.get("email"));
        Assertions.assertNotNull(meResponse.get("tokenExpiresAt"));
    }

    @Test
    void testGetMeKoWithoutToken() {
        Map<String, Object> response = authService.getMe(null);
        Assertions.assertEquals("Token manquant ou invalide", response.get("error"));
    }

    @Test
    void testGetMeKoNoBearerPrefix() {
        Map<String, Object> response = authService.getMe("token-sans-bearer");
        Assertions.assertEquals("Token manquant ou invalide", response.get("error"));
    }

    @Test
    void testGetMeKoUnknownToken() {
        Map<String, Object> response = authService.getMe("Bearer token-inconnu");
        Assertions.assertEquals("Utilisateur non trouvé pour ce token", response.get("error"));
    }

    @Test
    void testGetMeKoExpiredToken() {
        registerDefaultUser();

        User user = userRepository.findByEmail("poun@gmail.com").orElseThrow();
        user.setToken("token-expire");
        user.setTokenExpiresAt(LocalDateTime.now().minusMinutes(1));
        userRepository.save(user);

        Map<String, Object> response = authService.getMe("Bearer token-expire");
        Assertions.assertEquals("Token expiré ou invalide", response.get("error"));
    }

    // ─── Logout ───────────────────────────────────────────────────────────────

    @Test
    void testLogoutOk() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        Map<String, Object> loginResponse = authService.login(toLoginRequest(proof));
        String token = (String) loginResponse.get("accessToken");

        Map<String, Object> logoutResponse = authService.logout("Bearer " + token);
        Assertions.assertEquals("Déconnexion réussie", logoutResponse.get("message"));

        User user = userRepository.findByEmail("poun@gmail.com").orElseThrow();
        Assertions.assertNull(user.getToken());
        Assertions.assertNull(user.getTokenExpiresAt());
    }

    @Test
    void testLogoutKoWithoutToken() {
        Map<String, Object> response = authService.logout(null);
        Assertions.assertEquals("Token manquant ou invalide", response.get("error"));
    }

    @Test
    void testLogoutKoNoBearerPrefix() {
        Map<String, Object> response = authService.logout("token-sans-bearer");
        Assertions.assertEquals("Token manquant ou invalide", response.get("error"));
    }

    @Test
    void testLogoutKoUnknownToken() {
        Map<String, Object> response = authService.logout("Bearer token-inconnu");
        Assertions.assertEquals("Utilisateur non trouvé", response.get("error"));
    }

    // ─── changePassword ───────────────────────────────────────────────────────

    @Test
    void shouldChangePasswordSuccessfully() {
        String token = registerAndLogin("change.ok@test.com", "Ancien123!@AB");

        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setOldPassword("Ancien123!@AB");
        req.setNewPassword("Nouveau456!@CD");

        Map<String, Object> response = authService.changePassword("Bearer " + token, req);

        Assertions.assertEquals("Mot de passe changé avec succès", response.get("message"));

        User user = userRepository.findByEmail("change.ok@test.com").orElseThrow();
        Assertions.assertEquals("Nouveau456!@CD",
                passwordCryptoService.decrypt(user.getPasswordEncrypted()));
    }

    @Test
    void shouldRefuseChangePasswordWhenOldPasswordIsWrong() {
        String token = registerAndLogin("change.wrong@test.com", "Ancien123!@AB");

        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setOldPassword("MauvaisAncien!@1");
        req.setNewPassword("Nouveau456!@CD");

        Map<String, Object> response = authService.changePassword("Bearer " + token, req);

        Assertions.assertEquals("Ancien mot de passe incorrect", response.get("error"));
    }

    @Test
    void shouldRefuseChangePasswordWhenNewPasswordIsWeak() {
        String token = registerAndLogin("change.weak@test.com", "Ancien123!@AB");

        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setOldPassword("Ancien123!@AB");
        req.setNewPassword("faible"); // trop court, pas de majuscule, pas de chiffre, pas de spécial

        Map<String, Object> response = authService.changePassword("Bearer " + token, req);

        Assertions.assertNotNull(response.get("error"));
    }

    @Test
    void shouldRefuseChangePasswordWhenTokenIsNull() {
        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setOldPassword("Ancien123!@AB");
        req.setNewPassword("Nouveau456!@CD");

        Map<String, Object> response = authService.changePassword(null, req);

        Assertions.assertEquals("Token manquant ou invalide", response.get("error"));
    }

    @Test
    void shouldRefuseChangePasswordWhenTokenHasNoBearerPrefix() {
        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setOldPassword("Ancien123!@AB");
        req.setNewPassword("Nouveau456!@CD");

        Map<String, Object> response = authService.changePassword("token-sans-bearer", req);

        Assertions.assertEquals("Token manquant ou invalide", response.get("error"));
    }

    @Test
    void shouldRefuseChangePasswordWhenRequestIsNull() {
        Map<String, Object> response = authService.changePassword("Bearer token-quelconque", null);

        Assertions.assertEquals("Requête invalide", response.get("error"));
    }

    @Test
    void shouldRefuseChangePasswordWhenOldPasswordIsBlank() {
        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setOldPassword("   ");
        req.setNewPassword("Nouveau456!@CD");

        Map<String, Object> response = authService.changePassword("Bearer token-quelconque", req);

        Assertions.assertEquals("Ancien mot de passe obligatoire", response.get("error"));
    }

    @Test
    void shouldRefuseChangePasswordWhenNewPasswordIsBlank() {
        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setOldPassword("Ancien123!@AB");
        req.setNewPassword("   ");

        Map<String, Object> response = authService.changePassword("Bearer token-quelconque", req);

        Assertions.assertEquals("Nouveau mot de passe obligatoire", response.get("error"));
    }

    @Test
    void shouldRefuseChangePasswordWhenTokenUnknown() {
        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setOldPassword("Ancien123!@AB");
        req.setNewPassword("Nouveau456!@CD");

        Map<String, Object> response = authService.changePassword("Bearer token-inconnu-xyz", req);

        Assertions.assertEquals("Utilisateur non trouvé pour ce token", response.get("error"));
    }

    @Test
    void shouldRefuseChangePasswordWhenTokenExpired() {
        RegisterRequest reg = new RegisterRequest();
        reg.setName("Test");
        reg.setEmail("expired.cp@test.com");
        reg.setPassword("Ancien123!@AB");
        authService.register(reg);

        User user = userRepository.findByEmail("expired.cp@test.com").orElseThrow();
        user.setToken("token-expired-cp");
        user.setTokenExpiresAt(LocalDateTime.now().minusMinutes(5));
        userRepository.save(user);

        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setOldPassword("Ancien123!@AB");
        req.setNewPassword("Nouveau456!@CD");

        Map<String, Object> response = authService.changePassword("Bearer token-expired-cp", req);

        Assertions.assertEquals("Token expiré ou invalide", response.get("error"));
    }

    // ─── AuthController Integration (corrigés) ────────────────────────────────

    /**
     * Tests d'intégration du controller Auth.
     * ✅ Fix : les assertions HTTP étaient incorrectes.
     *    - /me sans token → 200 avec {error: ...} car pas de Spring Security
     *    - /logout sans token → 200 avec {error: ...} car header optional
     *    - change-password → PUT (corrigé dans AuthController)
     */
    @SpringBootTest(classes = AuthApplication.class)
    @AutoConfigureMockMvc
    @ActiveProfiles("test")
    static class AuthControllerIntegrationTest {

        private static final String AUTH_URL = "/api/auth";

        @Autowired
        private ObjectMapper objectMapper;

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private HmacService hmacService;

        private RegisterRequest buildRegisterRequest(String name, String email, String password) {
            RegisterRequest request = new RegisterRequest();
            request.setName(name);
            request.setEmail(email);
            request.setPassword(password);
            return request;
        }

        private LoginRequest buildLoginRequest(String email, String password) {
            LoginRequest request = new LoginRequest();
            long timestamp = System.currentTimeMillis() / 1000;
            String nonce = "nonce-" + System.nanoTime();
            String message = email + ":" + nonce + ":" + timestamp;
            String hmac = hmacService.hmacSha256(password, message);
            request.setEmail(email);
            request.setNonce(nonce);
            request.setTimestamp(timestamp);
            request.setHmac(hmac);
            return request;
        }

        private MvcResult postRegister(RegisterRequest request) throws Exception {
            return mockMvc.perform(
                    org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                            .post(AUTH_URL + "/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request))
            ).andReturn();
        }

        private MvcResult postLogin(LoginRequest request) throws Exception {
            return mockMvc.perform(
                    org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                            .post(AUTH_URL + "/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request))
            ).andReturn();
        }

        @Test
        void testRegisterSuccess() throws Exception {
            RegisterRequest request = buildRegisterRequest("Jean", "jean.ctrl@gmail.com", "Azerty1234!@");
            MvcResult result = postRegister(request);
            Assertions.assertEquals(200, result.getResponse().getStatus());
        }

        @Test
        void testRegisterDuplicate() throws Exception {
            RegisterRequest request = buildRegisterRequest("Sara", "sara.ctrl@gmail.com", "Azerty1234!@");
            postRegister(request);
            MvcResult result = postRegister(request);
            // GlobalExceptionHandler renvoie 400 pour RuntimeException
            Assertions.assertEquals(400, result.getResponse().getStatus());
        }

        @Test
        void testLoginSuccess() throws Exception {
            postRegister(buildRegisterRequest("Marie", "marie.ctrl@gmail.com", "Azerty1234!@"));
            MvcResult result = postLogin(buildLoginRequest("marie.ctrl@gmail.com", "Azerty1234!@"));
            Assertions.assertEquals(200, result.getResponse().getStatus());
            Assertions.assertTrue(result.getResponse().getContentAsString().contains("accessToken"));
        }

        @Test
        void testLoginUserNotFound() throws Exception {
            MvcResult result = postLogin(buildLoginRequest("no.ctrl@gmail.com", "Azerty1234!@"));
            Assertions.assertEquals(400, result.getResponse().getStatus());
        }

        @Test
        void testLoginInvalidHmac() throws Exception {
            postRegister(buildRegisterRequest("Paul", "paul.ctrl@gmail.com", "Azerty1234!@"));

            LoginRequest loginRequest = buildLoginRequest("paul.ctrl@gmail.com", "Azerty1234!@");
            loginRequest.setHmac("hmac-invalide");
            MvcResult result = postLogin(loginRequest);

            Assertions.assertEquals(400, result.getResponse().getStatus());
        }

        /**
         * /me sans token → 200 avec body {"error": "Token manquant ou invalide"}
         * ✅ Fix : la version précédente attendait 401 à tort.
         * Il n'y a pas de Spring Security configuré, le header est @RequestHeader(required=false).
         */
        @Test
        void testMeWithoutToken() throws Exception {
            MvcResult result = mockMvc.perform(
                    org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                            .get(AUTH_URL + "/me")
            ).andReturn();

            String body = result.getResponse().getContentAsString();
            Assertions.assertTrue(
                    body.contains("Token manquant") || body.contains("invalide"),
                    "La réponse doit indiquer que le token est manquant ou invalide"
            );
        }

        /**
         * logout sans token → 200 avec body {"error": "Token manquant ou invalide"}
         * ✅ Fix : la version précédente attendait 401 à tort.
         */
        @Test
        void testLogoutWithoutToken() throws Exception {
            MvcResult result = mockMvc.perform(
                    org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                            .post(AUTH_URL + "/logout")
            ).andReturn();

            String body = result.getResponse().getContentAsString();
            Assertions.assertTrue(
                    body.contains("Token manquant") || body.contains("invalide"),
                    "La réponse doit indiquer que le token est manquant ou invalide"
            );
        }

        /**
         * Vérifie que change-password via PUT retourne 400 si Authorization manquant.
         * (Spring lève MissingRequestHeaderException → 400)
         */
        @Test
        void testChangePasswordPutWithoutAuthHeader() throws Exception {
            String body = "{\"oldPassword\":\"Ancien123!@AB\",\"newPassword\":\"Nouveau456!@CD\"}";

            MvcResult result = mockMvc.perform(
                    org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                            .put(AUTH_URL + "/change-password")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body)
            ).andReturn();

            // Spring retourne 400 car @RequestHeader("Authorization") est required=true
            Assertions.assertEquals(400, result.getResponse().getStatus());
        }
    }
}
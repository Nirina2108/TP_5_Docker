package com.example.auth.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.stage.Stage;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Interface JavaFX simple pour tester l'API d'authentification du TP_5.
 *
 * Cette interface permet de :
 * - inscrire un utilisateur
 * - demander une preuve client HMAC
 * - effectuer le login sécurisé
 * - récupérer le profil avec /me
 * - effectuer le logout
 *
 * Le backend doit être lancé sur le port 8000.
 *
 * @author Poun
 * @version 5.3
 */
public class AuthClientUI extends Application {

    /**
     * URL de base de l'API.
     */
    private static final String BASE_URL = "http://127.0.0.1:8000/api/auth";

    /**
     * Client HTTP Java.
     */
    private final HttpClient httpClient = HttpClient.newHttpClient();

    /**
     * Convertisseur JSON.
     */
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Champ nom.
     */
    private final TextField nameField = new TextField();

    /**
     * Champ email.
     */
    private final TextField emailField = new TextField();

    /**
     * Champ mot de passe.
     */
    private final PasswordField passwordField = new PasswordField();

    /**
     * Label d'affichage de la force du mot de passe.
     */
    private final Label passwordStrengthLabel = new Label("Force du mot de passe : -");

    /**
     * Champ nonce retourné par /client-proof.
     */
    private final TextField nonceField = new TextField();

    /**
     * Champ timestamp retourné par /client-proof.
     */
    private final TextField timestampField = new TextField();

    /**
     * Champ hmac retourné par /client-proof.
     */
    private final TextField hmacField = new TextField();

    /**
     * Champ token retourné par /login.
     */
    private final TextField tokenField = new TextField();

    /**
     * Zone d'affichage des réponses.
     */
    private final TextArea resultArea = new TextArea();

    /**
     * Point d'entrée JavaFX.
     *
     * @param stage fenêtre principale
     */
    @Override
    public void start(Stage stage) {
        nameField.setPromptText("Nom");
        emailField.setPromptText("Email");
        passwordField.setPromptText("Mot de passe");

        nonceField.setPromptText("Nonce");
        timestampField.setPromptText("Timestamp");
        hmacField.setPromptText("HMAC");
        tokenField.setPromptText("Access Token");

        nonceField.setEditable(false);
        timestampField.setEditable(false);
        hmacField.setEditable(false);

        resultArea.setEditable(false);
        resultArea.setPrefHeight(260);
        resultArea.setWrapText(true);

        applyModernFieldStyle(nameField);
        applyModernFieldStyle(emailField);
        applyModernFieldStyle(passwordField);
        applyModernFieldStyle(nonceField);
        applyModernFieldStyle(timestampField);
        applyModernFieldStyle(hmacField);
        applyModernFieldStyle(tokenField);

        resultArea.setStyle(
                "-fx-control-inner-background: #0f172a;" +
                        "-fx-background-color: #0f172a;" +
                        "-fx-text-fill: #e2e8f0;" +
                        "-fx-font-family: 'Consolas';" +
                        "-fx-font-size: 13px;" +
                        "-fx-border-color: #334155;" +
                        "-fx-border-radius: 14;" +
                        "-fx-background-radius: 14;" +
                        "-fx-padding: 12;"
        );

        passwordStrengthLabel.setStyle(
                "-fx-font-weight: bold;" +
                        "-fx-font-size: 13px;" +
                        "-fx-text-fill: #94a3b8;"
        );

        passwordField.textProperty().addListener((observable, oldValue, newValue) -> updatePasswordStrength(newValue));

        Button registerButton = new Button("Register");
        Button proofButton = new Button("Client Proof");
        Button loginButton = new Button("Login");
        Button meButton = new Button("/me");
        Button logoutButton = new Button("Logout");
        Button clearButton = new Button("Clear");

        applyModernButtonStyle(registerButton, "#2563eb");
        applyModernButtonStyle(proofButton, "#7c3aed");
        applyModernButtonStyle(loginButton, "#16a34a");
        applyModernButtonStyle(meButton, "#ea580c");
        applyModernButtonStyle(logoutButton, "#dc2626");
        applyModernButtonStyle(clearButton, "#475569");

        registerButton.setOnAction(e -> register());
        proofButton.setOnAction(e -> generateClientProof());
        loginButton.setOnAction(e -> login());
        meButton.setOnAction(e -> getMe());
        logoutButton.setOnAction(e -> logout());
        clearButton.setOnAction(e -> clearFields());

        GridPane grid = new GridPane();
        grid.setHgap(12);
        grid.setVgap(12);
        grid.setPadding(new Insets(20));
        grid.setStyle(
                "-fx-background-color: linear-gradient(to bottom right, #111827, #1f2937);" +
                        "-fx-background-radius: 18;"
        );

        Label titleLabel = new Label("TP_5 - Interface de test Auth");
        titleLabel.setStyle(
                "-fx-font-size: 24px;" +
                        "-fx-font-weight: bold;" +
                        "-fx-text-fill: white;"
        );

        Label subtitleLabel = new Label("Authentification sécurisée");
        subtitleLabel.setStyle(
                "-fx-font-size: 13px;" +
                        "-fx-text-fill: #cbd5e1;"
        );

        Label nameLabel = createStyledLabel("Nom :");
        Label emailLabel = createStyledLabel("Email :");
        Label passwordLabel = createStyledLabel("Mot de passe :");
        Label nonceLabel = createStyledLabel("Nonce :");
        Label timestampLabel = createStyledLabel("Timestamp :");
        Label hmacLabel = createStyledLabel("HMAC :");
        Label tokenLabel = createStyledLabel("Token :");
        Label resultLabel = createStyledLabel("Résultat :");

        grid.add(titleLabel, 0, 0, 2, 1);
        grid.add(subtitleLabel, 0, 1, 2, 1);

        grid.add(nameLabel, 0, 2);
        grid.add(nameField, 1, 2);

        grid.add(emailLabel, 0, 3);
        grid.add(emailField, 1, 3);

        grid.add(passwordLabel, 0, 4);
        grid.add(passwordField, 1, 4);

        grid.add(passwordStrengthLabel, 1, 5);

        grid.add(nonceLabel, 0, 6);
        grid.add(nonceField, 1, 6);

        grid.add(timestampLabel, 0, 7);
        grid.add(timestampField, 1, 7);

        grid.add(hmacLabel, 0, 8);
        grid.add(hmacField, 1, 8);

        grid.add(tokenLabel, 0, 9);
        grid.add(tokenField, 1, 9);

        HBox buttonBox = new HBox(10, registerButton, proofButton, loginButton, meButton, logoutButton, clearButton);
        grid.add(buttonBox, 0, cd10, 2, 1);

        grid.add(resultLabel, 0, 11);
        grid.add(resultArea, 0, 12, 2, 1);

        Scene scene = new Scene(grid, 820, 700);
        stage.setTitle("TP_5 - Interface de test Auth");
        stage.setScene(scene);
        stage.show();
    }

    /**
     * Applique un style moderne à un champ texte.
     *
     * @param field champ à styliser
     */
    private void applyModernFieldStyle(TextField field) {
        field.setStyle(
                "-fx-background-color: #1e293b;" +
                        "-fx-text-fill: white;" +
                        "-fx-prompt-text-fill: #94a3b8;" +
                        "-fx-border-color: #334155;" +
                        "-fx-border-width: 1.2;" +
                        "-fx-border-radius: 12;" +
                        "-fx-background-radius: 12;" +
                        "-fx-padding: 10 12 10 12;" +
                        "-fx-font-size: 14px;"
        );
        field.setPrefHeight(42);
    }

    /**
     * Applique un style moderne à un bouton.
     *
     * @param button bouton concerné
     * @param color couleur principale
     */
    private void applyModernButtonStyle(Button button, String color) {
        button.setStyle(
                "-fx-background-color: " + color + ";" +
                        "-fx-text-fill: white;" +
                        "-fx-font-weight: bold;" +
                        "-fx-font-size: 13px;" +
                        "-fx-background-radius: 12;" +
                        "-fx-padding: 10 16 10 16;" +
                        "-fx-cursor: hand;"
        );
        button.setPrefHeight(40);
    }

    /**
     * Crée un label moderne.
     *
     * @param text texte du label
     * @return label stylisé
     */
    private Label createStyledLabel(String text) {
        Label label = new Label(text);
        label.setStyle(
                "-fx-text-fill: #e2e8f0;" +
                        "-fx-font-size: 14px;" +
                        "-fx-font-weight: bold;"
        );
        return label;
    }

    /**
     * Met à jour l'indicateur de force du mot de passe.
     *
     * @param password mot de passe saisi
     */
    private void updatePasswordStrength(String password) {
        if (password == null || password.isBlank()) {
            passwordStrengthLabel.setText("Force du mot de passe : -");
            passwordStrengthLabel.setStyle(
                    "-fx-font-weight: bold;" +
                            "-fx-font-size: 13px;" +
                            "-fx-text-fill: #94a3b8;"
            );
            return;
        }

        String strength = evaluatePasswordStrength(password);

        if ("Faible".equals(strength)) {
            passwordStrengthLabel.setText("Force du mot de passe : Faible");
            passwordStrengthLabel.setStyle(
                    "-fx-font-weight: bold;" +
                            "-fx-font-size: 13px;" +
                            "-fx-text-fill: #ef4444;"
            );
        } else if ("Moyen".equals(strength)) {
            passwordStrengthLabel.setText("Force du mot de passe : Moyen");
            passwordStrengthLabel.setStyle(
                    "-fx-font-weight: bold;" +
                            "-fx-font-size: 13px;" +
                            "-fx-text-fill: #f59e0b;"
            );
        } else {
            passwordStrengthLabel.setText("Force du mot de passe : Fort");
            passwordStrengthLabel.setStyle(
                    "-fx-font-weight: bold;" +
                            "-fx-font-size: 13px;" +
                            "-fx-text-fill: #22c55e;"
            );
        }
    }

    /**
     * Évalue simplement la robustesse du mot de passe.
     *
     * Règles simples :
     * - Faible : trop court ou très peu varié
     * - Moyen : correct mais incomplet
     * - Fort : assez long avec plusieurs types de caractères
     *
     * @param password mot de passe
     * @return Faible, Moyen ou Fort
     */
    private String evaluatePasswordStrength(String password) {
        int score = 0;

        if (password.length() >= 8) {
            score++;
        }

        if (containsLowerCase(password)) {
            score++;
        }

        if (containsUpperCase(password)) {
            score++;
        }

        if (containsDigit(password)) {
            score++;
        }

        if (containsSpecialCharacter(password)) {
            score++;
        }

        if (score <= 2) {
            return "Faible";
        }

        if (score <= 4) {
            return "Moyen";
        }

        return "Fort";
    }

    /**
     * Vérifie si le texte contient une minuscule.
     *
     * @param text texte à tester
     * @return true si au moins une minuscule existe
     */
    private boolean containsLowerCase(String text) {
        for (char c : text.toCharArray()) {
            if (Character.isLowerCase(c)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Vérifie si le texte contient une majuscule.
     *
     * @param text texte à tester
     * @return true si au moins une majuscule existe
     */
    private boolean containsUpperCase(String text) {
        for (char c : text.toCharArray()) {
            if (Character.isUpperCase(c)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Vérifie si le texte contient un chiffre.
     *
     * @param text texte à tester
     * @return true si au moins un chiffre existe
     */
    private boolean containsDigit(String text) {
        for (char c : text.toCharArray()) {
            if (Character.isDigit(c)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Vérifie si le texte contient un caractère spécial.
     *
     * @param text texte à tester
     * @return true si au moins un caractère spécial existe
     */
    private boolean containsSpecialCharacter(String text) {
        for (char c : text.toCharArray()) {
            if (!Character.isLetterOrDigit(c)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Envoie une requête d'inscription.
     */
    private void register() {
        try {
            String jsonBody = String.format(
                    """
                    {
                      "name": "%s",
                      "email": "%s",
                      "password": "%s"
                    }
                    """,
                    escapeJson(nameField.getText()),
                    escapeJson(emailField.getText()),
                    escapeJson(passwordField.getText())
            );

            String response = sendPost(BASE_URL + "/register", jsonBody, null);
            resultArea.setText("REGISTER\n\n" + prettyJson(response));

        } catch (Exception e) {
            resultArea.setText("Erreur register : " + e.getMessage());
        }
    }

    /**
     * Appelle /client-proof pour récupérer nonce, timestamp et hmac.
     */
    private void generateClientProof() {
        try {
            String jsonBody = String.format(
                    """
                    {
                      "email": "%s",
                      "password": "%s"
                    }
                    """,
                    escapeJson(emailField.getText()),
                    escapeJson(passwordField.getText())
            );

            String response = sendPost(BASE_URL + "/client-proof", jsonBody, null);
            JsonNode root = objectMapper.readTree(response);

            nonceField.setText(readText(root, "nonce"));
            timestampField.setText(readText(root, "timestamp"));
            hmacField.setText(readText(root, "hmac"));

            resultArea.setText("CLIENT-PROOF\n\n" + prettyJson(response));

        } catch (Exception e) {
            resultArea.setText("Erreur client-proof : " + e.getMessage());
        }
    }

    /**
     * Envoie la requête de login HMAC.
     */
    private void login() {
        try {
            String jsonBody = String.format(
                    """
                    {
                      "email": "%s",
                      "nonce": "%s",
                      "timestamp": %s,
                      "hmac": "%s"
                    }
                    """,
                    escapeJson(emailField.getText()),
                    escapeJson(nonceField.getText()),
                    timestampField.getText().isBlank() ? "0" : timestampField.getText(),
                    escapeJson(hmacField.getText())
            );

            String response = sendPost(BASE_URL + "/login", jsonBody, null);
            JsonNode root = objectMapper.readTree(response);

            String token = readText(root, "accessToken");
            tokenField.setText(token);

            resultArea.setText("LOGIN\n\n" + prettyJson(response));

        } catch (Exception e) {
            resultArea.setText("Erreur login : " + e.getMessage());
        }
    }

    /**
     * Appelle l'endpoint /me avec le token Bearer.
     */
    private void getMe() {
        try {
            String token = tokenField.getText();

            if (token == null || token.isBlank()) {
                resultArea.setText("Token vide. Fais d'abord le login.");
                return;
            }

            String response = sendGet(BASE_URL + "/me", token);
            resultArea.setText("/ME\n\n" + prettyJson(response));

        } catch (Exception e) {
            resultArea.setText("Erreur /me : " + e.getMessage());
        }
    }

    /**
     * Appelle l'endpoint logout avec le token Bearer.
     */
    private void logout() {
        try {
            String token = tokenField.getText();

            if (token == null || token.isBlank()) {
                resultArea.setText("Token vide. Fais d'abord le login.");
                return;
            }

            String response = sendPost(BASE_URL + "/logout", "{}", token);
            resultArea.setText("LOGOUT\n\n" + prettyJson(response));

        } catch (Exception e) {
            resultArea.setText("Erreur logout : " + e.getMessage());
        }
    }

    /**
     * Vide quelques champs de sortie.
     */
    private void clearFields() {
        nonceField.clear();
        timestampField.clear();
        hmacField.clear();
        tokenField.clear();
        resultArea.clear();
        passwordField.clear();
        passwordStrengthLabel.setText("Force du mot de passe : -");
        passwordStrengthLabel.setStyle(
                "-fx-font-weight: bold;" +
                        "-fx-font-size: 13px;" +
                        "-fx-text-fill: #94a3b8;"
        );
    }

    /**
     * Envoie une requête POST JSON.
     *
     * @param url adresse cible
     * @param jsonBody corps JSON
     * @param token token Bearer éventuel
     * @return corps de réponse uniquement
     * @throws IOException erreur réseau
     * @throws InterruptedException interruption
     */
    private String sendPost(String url, String jsonBody, String token) throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json");

        if (token != null && !token.isBlank()) {
            builder.header("Authorization", "Bearer " + token);
        }

        HttpRequest request = builder
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        return response.body();
    }

    /**
     * Envoie une requête GET.
     *
     * @param url adresse cible
     * @param token token Bearer
     * @return corps de réponse uniquement
     * @throws IOException erreur réseau
     * @throws InterruptedException interruption
     */
    private String sendGet(String url, String token) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + token)
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        return response.body();
    }

    /**
     * Lit un champ JSON et le retourne sous forme texte.
     *
     * @param root objet JSON
     * @param field nom du champ
     * @return valeur texte ou chaîne vide
     */
    private String readText(JsonNode root, String field) {
        JsonNode node = root.get(field);
        return node == null ? "" : node.asText();
    }

    /**
     * Formate un JSON pour l'affichage.
     *
     * @param rawJson json brut
     * @return json indenté si possible
     */
    private String prettyJson(String rawJson) {
        try {
            Object json = objectMapper.readValue(rawJson, Object.class);
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
        } catch (Exception e) {
            return rawJson;
        }
    }

    /**
     * Échappe simplement les guillemets dans une chaîne JSON.
     *
     * @param value texte source
     * @return texte échappé
     */
    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /**
     * Point d'entrée principal.
     *
     * @param args arguments console
     */
    public static void main(String[] args) {
        launch(args);
    }
}
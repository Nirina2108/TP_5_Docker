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
 * @version 5.1
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

        Button registerButton = new Button("Register");
        Button proofButton = new Button("Client Proof");
        Button loginButton = new Button("Login");
        Button meButton = new Button("/me");
        Button logoutButton = new Button("Logout");
        Button clearButton = new Button("Clear");

        registerButton.setOnAction(e -> register());
        proofButton.setOnAction(e -> generateClientProof());
        loginButton.setOnAction(e -> login());
        meButton.setOnAction(e -> getMe());
        logoutButton.setOnAction(e -> logout());
        clearButton.setOnAction(e -> clearFields());

        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(15));

        grid.add(new Label("Nom :"), 0, 0);
        grid.add(nameField, 1, 0);

        grid.add(new Label("Email :"), 0, 1);
        grid.add(emailField, 1, 1);

        grid.add(new Label("Mot de passe :"), 0, 2);
        grid.add(passwordField, 1, 2);

        grid.add(new Label("Nonce :"), 0, 3);
        grid.add(nonceField, 1, 3);

        grid.add(new Label("Timestamp :"), 0, 4);
        grid.add(timestampField, 1, 4);

        grid.add(new Label("HMAC :"), 0, 5);
        grid.add(hmacField, 1, 5);

        grid.add(new Label("Token :"), 0, 6);
        grid.add(tokenField, 1, 6);

        HBox buttonBox = new HBox(10, registerButton, proofButton, loginButton, meButton, logoutButton, clearButton);
        grid.add(buttonBox, 0, 7, 2, 1);

        grid.add(new Label("Résultat :"), 0, 8);
        grid.add(resultArea, 0, 9, 2, 1);

        Scene scene = new Scene(grid, 760, 560);
        stage.setTitle("TP_5 - Interface de test Auth");
        stage.setScene(scene);
        stage.show();
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
package com.example.auth.client;

import com.example.auth.validator.PasswordStrengthUtil;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Separator;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

/**
 * Interface JavaFX simple pour tester l'authentification.
 *
 * @author Poun
 * @version 2.5
 */
public class AuthClientUI extends Application {

    private TextField registerNameField;
    private TextField registerEmailField;
    private PasswordField registerPasswordField;
    private PasswordField registerConfirmPasswordField;
    private Label passwordStatusLabel;
    private Label registerMessageLabel;

    private TextField loginEmailField;
    private PasswordField loginPasswordField;
    private Label loginMessageLabel;

    private final PasswordStrengthUtil passwordStrengthUtil = new PasswordStrengthUtil();

    @Override
    public void start(Stage stage) {
        Label titleLabel = new Label("TP2 - Authentification fragile");
        titleLabel.setStyle("-fx-font-size: 20px; -fx-font-weight: bold;");

        Label registerTitle = new Label("Inscription");
        registerTitle.setStyle("-fx-font-size: 16px; -fx-font-weight: bold;");

        registerNameField = new TextField();
        registerNameField.setPromptText("Nom");

        registerEmailField = new TextField();
        registerEmailField.setPromptText("Email");

        registerPasswordField = new PasswordField();
        registerPasswordField.setPromptText("Mot de passe");

        registerConfirmPasswordField = new PasswordField();
        registerConfirmPasswordField.setPromptText("Confirmer le mot de passe");

        passwordStatusLabel = new Label("Saisissez un mot de passe");
        passwordStatusLabel.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");

        registerMessageLabel = new Label();

        Button registerButton = new Button("S'inscrire");
        registerButton.setMaxWidth(Double.MAX_VALUE);
        registerButton.setOnAction(event -> handleRegister());

        registerPasswordField.textProperty().addListener((observable, oldValue, newValue) -> updatePasswordIndicator());
        registerConfirmPasswordField.textProperty().addListener((observable, oldValue, newValue) -> updatePasswordIndicator());

        Label loginTitle = new Label("Connexion");
        loginTitle.setStyle("-fx-font-size: 16px; -fx-font-weight: bold;");

        loginEmailField = new TextField();
        loginEmailField.setPromptText("Email");

        loginPasswordField = new PasswordField();
        loginPasswordField.setPromptText("Mot de passe");

        loginMessageLabel = new Label();

        Button loginButton = new Button("Se connecter");
        loginButton.setMaxWidth(Double.MAX_VALUE);
        loginButton.setOnAction(event -> handleLogin());

        VBox root = new VBox(10);
        root.setPadding(new Insets(20));
        root.setAlignment(Pos.TOP_CENTER);

        root.getChildren().addAll(
                titleLabel,
                new Separator(),

                registerTitle,
                registerNameField,
                registerEmailField,
                registerPasswordField,
                registerConfirmPasswordField,
                passwordStatusLabel,
                registerButton,
                registerMessageLabel,

                new Separator(),

                loginTitle,
                loginEmailField,
                loginPasswordField,
                loginButton,
                loginMessageLabel
        );

        Scene scene = new Scene(root, 420, 520);

        stage.setTitle("TP2 Auth Client");
        stage.setScene(scene);
        stage.show();
    }

    private void updatePasswordIndicator() {
        String password = registerPasswordField.getText();
        String confirmPassword = registerConfirmPasswordField.getText();

        String level = passwordStrengthUtil.evaluate(password);
        String message = passwordStrengthUtil.getMessage(password, confirmPassword);

        passwordStatusLabel.setText(message);

        if (!passwordStrengthUtil.isPolicyValid(password)) {
            passwordStatusLabel.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");
            return;
        }

        if (!passwordStrengthUtil.passwordsMatch(password, confirmPassword)) {
            passwordStatusLabel.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");
            return;
        }

        if (PasswordStrengthUtil.GREEN.equals(level)) {
            passwordStatusLabel.setStyle("-fx-text-fill: green; -fx-font-weight: bold;");
        } else {
            passwordStatusLabel.setStyle("-fx-text-fill: orange; -fx-font-weight: bold;");
        }
    }

    private void handleRegister() {
        String name = registerNameField.getText();
        String email = registerEmailField.getText();
        String password = registerPasswordField.getText();
        String confirmPassword = registerConfirmPasswordField.getText();

        if (name == null || name.isBlank()) {
            registerMessageLabel.setText("Le nom est obligatoire.");
            registerMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        if (email == null || email.isBlank()) {
            registerMessageLabel.setText("L'email est obligatoire.");
            registerMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        if (!passwordStrengthUtil.isPolicyValid(password)) {
            registerMessageLabel.setText("Le mot de passe ne respecte pas les règles.");
            registerMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        if (!passwordStrengthUtil.passwordsMatch(password, confirmPassword)) {
            registerMessageLabel.setText("La confirmation du mot de passe est différente.");
            registerMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        registerMessageLabel.setText("Formulaire valide. Inscription prête à être envoyée.");
        registerMessageLabel.setStyle("-fx-text-fill: green;");
    }

    private void handleLogin() {
        String email = loginEmailField.getText();
        String password = loginPasswordField.getText();

        if (email == null || email.isBlank()) {
            loginMessageLabel.setText("L'email est obligatoire.");
            loginMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        if (password == null || password.isBlank()) {
            loginMessageLabel.setText("Le mot de passe est obligatoire.");
            loginMessageLabel.setStyle("-fx-text-fill: red;");
            return;
        }

        loginMessageLabel.setText("Connexion prête à être envoyée.");
        loginMessageLabel.setStyle("-fx-text-fill: green;");
    }

    public static void main(String[] args) {
        launch(args);
    }
}
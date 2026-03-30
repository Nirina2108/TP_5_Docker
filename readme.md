# TP_5 - Authentification sécurisée avec Docker, JavaFX et MySQL

## 1. Présentation du projet

Ce projet correspond au TP_5 de l'application d'authentification sécurisée réalisée en Java avec Spring Boot.

L'objectif principal de cette version est de :
- exécuter l'application avec Docker,
- utiliser une base de données MySQL conteneurisée,
- tester les fonctionnalités via une interface JavaFX,
- conserver les améliorations de sécurité des TPs précédents,
- visualiser les données utilisateurs dans MySQL et phpMyAdmin.

Le projet reprend les fonctionnalités avancées des versions précédentes :
- inscription utilisateur,
- génération d'une preuve client,
- authentification sécurisée avec HMAC,
- récupération du profil connecté,
- déconnexion,
- indicateur visuel de force du mot de passe dans l'interface.

---

## 2. Technologies utilisées

- Java 17
- Spring Boot
- Spring Data JPA
- MySQL 8
- Docker
- Docker Compose
- JavaFX
- Maven

---

## 3. Fonctionnalités principales

### Backend
- API REST d'authentification
- inscription d'un utilisateur
- login sécurisé avec nonce, timestamp et HMAC
- endpoint `/me`
- endpoint `/logout`

### Interface JavaFX
- formulaire de test utilisateur
- affichage des champs nécessaires à l'authentification
- affichage des réponses JSON en bas de l'interface
- indicateur de force du mot de passe :
  - faible en rouge
  - moyen en orange
  - fort en vert

### Base de données
- MySQL exécuté dans Docker
- persistance des données via volume Docker
- visualisation possible avec phpMyAdmin

---

## 4. Structure du projet

```text
src/
 ├── main/
 │   ├── java/com/example/auth/
 │   │   ├── client/       -> interface JavaFX
 │   │   ├── controller/   -> endpoints REST
 │   │   ├── dto/          -> objets de requête/réponse
 │   │   ├── entity/       -> entités JPA
 │   │   ├── repository/   -> accès base de données
 │   │   ├── service/      -> logique métier
 │   │   └── AuthApplication.java
 │   └── resources/
 │       └── application.properties
 ├── test/                 -> tests unitaires
Dockerfile
docker-compose.yml
pom.xml
README.md
# TP_5 – Dockerisation d’une application Spring Boot sécurisée

## Description

Ce projet correspond au TP_5 du module d’authentification.
Il consiste à dockeriser une application Spring Boot sécurisée développée dans les TP précédents.

L’application implémente une authentification forte basée sur HMAC avec :
- gestion des utilisateurs
- protection contre les attaques replay (nonce + timestamp)
- génération de token d’accès

---

## Architecture

[ Client (Postman) ]
        ↓
[ Spring Boot (Docker) ]
        ↓
[ MySQL (Docker) ]

---

## Technologies utilisées

- Java 17
- Spring Boot 3
- Spring Data JPA
- MySQL 8
- Docker
- Docker Compose

---

## Lancement du projet

### Prérequis

- Docker Desktop installé
- WSL2 activé

### Lancer

docker compose up --build

---

## Fonctionnement de l’authentification

### 1. Inscription

POST /api/auth/register

{
  "name": "Poun",
  "email": "poun@gmail.com",
  "password": "Poun_123456789_@@@@@"
}

---

### 2. Génération HMAC

POST /api/auth/client-proof

Réponse :
- nonce
- timestamp
- message
- hmac

---

### 3. Login sécurisé

POST /api/auth/login

{
  "email": "...",
  "nonce": "...",
  "timestamp": ...,
  "hmac": "..."
}

---

### 4. Route protégée

GET /api/auth/me
Authorization: Bearer TOKEN

---

## Commandes utiles

docker compose up --build
docker ps
docker logs tp5_app
docker compose down

---

## Résultat

- API fonctionnelle
- MySQL connecté
- Authentification HMAC opérationnelle
- Docker opérationnel

---

## Auteur

Poun Razafy

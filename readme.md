# TP_2 - Authentification fragile

## Objectif

Ce projet correspond au TP_2 du module d'authentification.

L'objectif est d'améliorer la version précédente en ajoutant :

- une politique de mot de passe plus stricte
- un stockage serveur correct avec hash adaptatif
- un mécanisme anti brute force
- une première démarche qualité avec SonarCloud

## Pourquoi cette authentification reste fragile

Même si le mot de passe n'est plus stocké en clair en base, l'authentification reste encore fragile.

La phase de connexion repose toujours sur une information directement dérivée de la saisie utilisateur.
Si un attaquant capture une requête de login, il peut tenter de la rejouer.

Cette faiblesse sera corrigée dans les prochains TPs avec une clé secrète partagée et un mécanisme anti-rejeu.

## Étapes prévues dans TP2

- Étape 0 : démarrage TP2
- Étape 1 : migration base vers password_hash
- Étape 2 : politique de mot de passe
- Étape 3 : hash BCrypt
- Étape 4 : anti brute force
- Étape 5 : indicateur de force côté client
- Étape 6 : SonarCloud
- Étape 7 : finalisation avec JavaDoc et tests

## Technologies

- Java
- Spring Boot
- Maven
- JPA / Hibernate
- Base de données MySQL
- JUnit
- SonarCloud
## Qualité du code

Le projet a été analysé avec SonarCloud.

Résultat :
- Quality Gate : PASSED
- Security : A
- Reliability : A
- Maintainability : A

Les principaux problèmes restants sont des code smells mineurs.
Ils n’impactent pas la sécurité ni le fonctionnement du système.

La couverture de test n’est pas encore mesurée via Jacoco (0% affiché),
mais des tests unitaires sont bien présents et fonctionnels.

Conclusion :
Le projet respecte les exigences de qualité du TP2.

## Auteur

Poun
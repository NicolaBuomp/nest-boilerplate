# NestJS Boilerplate Readme

## Introduzione

Questo progetto è un boilerplate per un'applicazione NestJS che include autenticazione, gestione degli utenti e un sistema di ruoli e permessi granulari.

### Struttura del Progetto

- **Autenticazione**: Sistema di autenticazione basato su JSON Web Tokens (JWT), che include access token e refresh token per garantire una migliore gestione delle sessioni.
- **Autorizzazione**: Sistema di ruoli e permessi per gestire l'accesso alle risorse dell'applicazione in modo granulare.
- **Gestione Utenti**: CRUD per gli utenti con validazione dei dati e gestione dei permessi.
- **Gestione Errori**: Filtro di eccezione globale e middleware di logging per una gestione coerente degli errori.

## Funzionalità Implementate

### 1. Autenticazione e Autorizzazione

- **JWT Access Token e Refresh Token**: Gli utenti ricevono un `access_token` per operazioni a breve termine e un `refresh_token` per estendere la sessione senza dover riloggare frequentemente.
  - **Endpoint per Registrazione**: Permette di registrare nuovi utenti, controllando se l'email è già in uso.
  - **Endpoint per Login**: Fornisce access token e refresh token per gestire l'autenticazione.
  - **Endpoint per Refresh Token**: Genera un nuovo access token utilizzando il refresh token.
  - **Logout**: Rimuove il refresh token salvato dall'utente per invalidare la sessione.

### 2. Sistema di Ruoli e Permessi

- **Ruoli**: Attualmente sono presenti ruoli come `admin` e `user`. Ogni ruolo ha permessi predefiniti.
- **Permessi Granulari**: Ogni ruolo ha una lista di permessi specifici, come `CREATE_RESOURCE`, `UPDATE_RESOURCE`, `DELETE_RESOURCE`, `VIEW_RESOURCE`, ecc.
  - **Permessi Definiti tramite Enum**: I permessi sono definiti in un enum per garantire coerenza e facilità di gestione.
  - **Decoratori e Guard**: Implementati decoratori (`@Permissions()`) e guard (`PermissionsGuard`) per proteggere gli endpoint in base ai permessi richiesti.

### 3. Gestione degli Utenti

- **CRUD per Utenti**: Endpoint per creare, visualizzare, aggiornare e gestire gli utenti.
- **Validazione degli Input**: I dati in ingresso per la registrazione e l'aggiornamento degli utenti sono validati tramite DTO (`CreateUserDto`).
- **Hashing delle Password**: Le password vengono hashate usando `bcrypt` prima di essere salvate nel database.

### 4. Gestione degli Errori e Logging

- **Filtro di Eccezione Globale**: Implementato un filtro globale (`AllExceptionsFilter`) per catturare e gestire tutte le eccezioni in un unico punto, garantendo risposte coerenti.
- **Middleware di Logging**: Un middleware (`LoggerMiddleware`) registra tutte le richieste HTTP, fornendo dettagli utili per il debugging.

## Endpoint Disponibili

### Autenticazione

- **POST /api/auth/register**: Registra un nuovo utente.
- **POST /api/auth/login**: Effettua il login dell'utente e restituisce access e refresh token.
- **POST /api/auth/refresh**: Rigenera un access token utilizzando il refresh token.
- **POST /api/auth/logout**: Effettua il logout dell'utente.

### Utenti

- **POST /api/users/create-user**: Crea un nuovo utente (protetto da permessi).
- **GET /api/users**: Ottiene la lista di tutti gli utenti (protetto da permessi).
- **GET /api/users/:id**: Ottiene le informazioni di un singolo utente (protetto da permessi).

## Configurazione

### Variabili d'Ambiente

Le variabili d'ambiente utilizzate includono:

- **`DB_HOST`**: Host del database.
- **`DB_PORT`**: Porta del database.
- **`DB_USERNAME`**: Username per il database.
- **`DB_PASSWORD`**: Password per il database.
- **`DB_NAME`**: Nome del database.
- **`JWT_SECRET`**: Segreto per firmare i token JWT.

### Installazione

1. Clona il repository:
   ```bash
   git clone <repository-url>
   ```
2. Installa le dipendenze:
   ```bash
   npm install
   ```
3. Crea un file `.env` con le variabili d'ambiente necessarie.
4. Avvia il server:
   ```bash
   npm run start:dev
   ```

## Tecnologie Utilizzate

- **NestJS**: Framework Node.js per applicazioni lato server.
- **TypeORM**: ORM per interagire con il database.
- **PostgreSQL**: Database relazionale utilizzato.
- **JWT**: Per la gestione dell'autenticazione e delle sessioni.

## Prossimi Passi

- **Gestione delle Email**: Implementare la verifica email e il reset della password.
- **Test Automatizzati**: Aggiungere test unitari e di integrazione per i servizi e i controller.
- **Health Check e Monitoraggio**: Aggiungere un endpoint `/health` e strumenti di monitoraggio come Prometheus o Grafana.

## Conclusioni

Questo boilerplate fornisce una solida base per sviluppare applicazioni NestJS con autenticazione e autorizzazione avanzate. È progettato per essere facilmente espandibile e adattabile a nuovi requisiti.

Sentiti libero di contribuire o segnalare problemi aprendo una issue su GitHub.

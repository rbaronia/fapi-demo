🏦 FAPI 2.0 Security Demo (Node.js)
This project demonstrates a fully functional Financial-grade API (FAPI 2.0) ecosystem using IBM Verify as the Identity Provider. It simulates an Open Banking flow where a Third-Party Provider (Client) securely accesses a user's financial data from a Bank API (Resource Server).

🌟 Key Features
FAPI 2.0 Security Profile: Enforces strict security including PAR (Pushed Authorization Requests), RAR (Rich Authorization Requests), and DPoP (Demonstrating Proof-of-Possession).

Private Key JWT: Client authentication using asymmetric keys (no shared secrets).

Fine-Grained Consent: IBM Verify calls the Bank via a Webhook to let the user select specific accounts (Savings vs Checking) during login.

Educational UI: The Client App features a "Tech Inspector" dashboard with real-time logs, decoded tokens, and an animated Mermaid.js sequence diagram.

🏗️ Architecture
The solution consists of two local Node.js applications and the IBM Verify cloud tenant.

client.js (The TPP / Aggregator):

Initiates the login flow using PAR & RAR.

Generates ephemeral DPoP keys (RSA/PS256) for every session.

Exchanges the Authorization Code for an Access Token bound to the DPoP key.

Visualizes the flow on http://localhost:3000.

bank.js (The Resource Server):

Protects the /accounts endpoint.

Validates the Access Token (signature, audience, expiry).

Validates the DPoP Proof (replay protection, binding).

Hosts the Consent Webhook used by IBM Verify to fetch user accounts during authorization.

IBM Verify (Authorization Server):

Authenticates the user.

Orchestrates consent via the webhook.

Issues the sender-constrained (DPoP) Access Token.

⚙️ IBM Verify Configuration
To run this demo, you must configure your IBM Verify tenant as follows:

1. Create the Application (OIDC)

Type: OpenID Connect / Custom Application.

Sign-on URL / Redirect URI: http://localhost:3000/callback

Token Endpoint Auth: private_key_jwt

Pushed Authorization Requests (PAR): Required.

DPoP: Enabled (Enforce DPoP for Token Exchange).

JWKS: Upload the public key (public.pem) extracted from your local private key.

2. Configure the API Resource

Create a new API Client in Verify to represent the Bank API.

Identifier (Audience): Note the UUID generated (e.g., aeaab16d-5753...). This goes into your .env as API_AUDIENCE.

3. Configure Fine-Grained Consent (Privacy)

Data Source: Create a generic HTTP web data source.

URL: https://<YOUR_NGROK>.ngrok-free.app/webhook/consent-options

Authentication: None (for this demo).

Purpose: Create a Purpose named "Account Access" (ID: account_access).

4. Attribute Mapping (The Glue)

In your OIDC Application settings > Attribute Mapping:

Target: Consent request

Source: Custom Rule (CEL).

Rule:

JavaScript
requestContext.scope.map(s, {"scope": s}) + hc.getAsJSON("https://YOUR_NGROK_ID.ngrok-free.app/webhook/consent-options", {"ngrok-skip-browser-warning": "true"}).accounts.map(account, {"purpose": "account_access", "scope": "account:" + account.id})
🚀 Setup & Installation
1. Prerequisites

Node.js (v18+)

Ngrok (to expose your local webhook to IBM Verify)

OpenSSL (to generate keys)

2. Generate Keys

Generate the RSA key pair used for private_key_jwt authentication.

Bash
# Generate Private Key
openssl genrsa -out private.key 2048

# Extract Public Key (Upload this content to IBM Verify Application JWKS)
openssl rsa -in private.key -pubout -out public.pem
3. Install Dependencies

Bash
npm install express express-session openid-client jose dotenv body-parser cookie-session
4. Configure Environment (.env)

Create a .env file in the root directory:

Ini, TOML
# --- IBM Verify Config ---
VERIFY_TENANT_URL=https://<YOUR_TENANT>.verify.ibm.com
# The Client ID from your OIDC Application
CLIENT_ID=Gw3... 
# The Unique ID of your API Resource (not the human name)
API_AUDIENCE=aeaab16d-5753-4bf2-bbb1-9aa77f2c0a65

# --- Local Client Config ---
REDIRECT_URI=http://localhost:3000/callback
PRIVATE_KEY_PATH=./private.key
# Key ID (kid) you assigned when uploading the key to Verify
KEY_ID=demo-key-01 
SIGNING_ALG=PS256
SESSION_SECRET=super_secret_dev_key

# --- Local Bank Config ---
BANK_API_URL=http://localhost:8080/accounts
🏃‍♂️ Running the Demo
Step 1: Start Ngrok

You must expose the Bank API webhook for IBM Verify to call it.

Bash
ngrok http 8080
Copy the HTTPS URL (e.g., https://d4a6...ngrok-free.app).

Update your IBM Verify Consent Rule and Data Source with this new URL.

Step 2: Start the Bank API

In a new terminal:

Bash
node bank.js
Output: 🚀 Bank API running on port 8080

Step 3: Start the Client App

In a new terminal:

Bash
node client.js
Output: 🌐 Animated UI running on http://localhost:3000

🎮 Usage Guide
Open Dashboard: Navigate to http://localhost:3000/login.

Login: You will be redirected to IBM Verify.

Consent:

Verify calls your local bank.js webhook.

You see a screen asking to select "Savings" or "Checking".

Select an account and approve.

Tech Inspector:

You are returned to the client.js Dashboard.

Review the Mermaid Sequence Diagram on the right.

Expand the Transaction Logs to see the raw PAR/RAR JSON.

Fetch Data:

Click "Execute API Call".

The client generates a DPoP Proof and calls the Bank.

The Bank validates the proof and returns the JSON data.

Security Demo:

Check the server console for the "SECURITY DEMO" banner.

Copy the generated curl command and try to run it in your terminal.

Result: It fails, proving that the token cannot be stolen and replayed.
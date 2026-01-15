require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { Issuer, generators } = require('openid-client');
const fs = require('fs');
const { createPrivateKey, generateKeyPairSync } = require('crypto');
const { decodeJwt, SignJWT, exportJWK } = require('jose');
const path = require('path');

const app = express();

// =============================================================================
// 1. CONFIGURATION
// =============================================================================
const CONFIG = {
    discovery_url: `${process.env.VERIFY_TENANT_URL}/oauth2/.well-known/openid-configuration`,
    client_id: process.env.CLIENT_ID,
    redirect_uri: process.env.REDIRECT_URI,
    private_key_path: path.resolve(process.env.PRIVATE_KEY_PATH || './private.key'),
    resource_url: process.env.BANK_API_URL,
    session_secret: process.env.SESSION_SECRET || 'super_secret_key',
    key_id: process.env.KEY_ID, 
    signing_alg: process.env.SIGNING_ALG || 'PS256',
    // READ TOGGLE FROM ENV
    enable_dpop: process.env.ENABLE_DPOP === 'true'
};

app.use(session({
    secret: CONFIG.session_secret,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

let client;

// =============================================================================
// 2. HELPER: Logger & Diagram Builder
// =============================================================================
const uiLog = (req, step, message, technicalData = null, diagramStep = null) => {
    if (!req.session.logs) req.session.logs = [];
    
    req.session.logs.push({ 
        time: new Date().toLocaleTimeString(), 
        step, 
        message, 
        data: technicalData ? JSON.stringify(technicalData, null, 2) : null 
    });

    if (diagramStep) {
        if (!req.session.diagram) req.session.diagram = [];
        req.session.diagram.push(diagramStep);
    }
    
    console.log(`[${step}] ${message}`);
};

async function init() {
    if (client) return;
    console.log(`🚀 Initializing Client (Mode: ${CONFIG.enable_dpop ? '🔐 FAPI/DPoP' : '🔓 Standard Bearer'})...`);
    const issuer = await Issuer.discover(CONFIG.discovery_url);
    const privateKeyPem = fs.readFileSync(CONFIG.private_key_path, 'utf8');

    client = new issuer.Client({
        client_id: CONFIG.client_id,
        token_endpoint_auth_method: 'private_key_jwt',
        id_token_signed_response_alg: CONFIG.signing_alg,
        token_endpoint_auth_signing_alg: CONFIG.signing_alg,
        require_pushed_authorization_requests: true 
    }, {
        keys: [{
            kty: 'RSA',
            kid: CONFIG.key_id, 
            ...createPrivateKey(privateKeyPem).export({ format: 'jwk' })
        }]
    });
}

// =============================================================================
// 3. ROUTES
// =============================================================================

// --- LOGIN ---
app.get('/login', async (req, res) => {
    try {
        await init();
        req.session.logs = [];
        req.session.diagram = [];

        uiLog(req, "INIT", `Starting Flow (DPoP: ${CONFIG.enable_dpop})`, null, 
            `Note over Client: 1. Init Flow (${CONFIG.enable_dpop ? 'DPoP' : 'Bearer'})`);

        // 1. DPoP Generation (Conditional)
        if (CONFIG.enable_dpop) {
            const { privateKey, publicKey } = generateKeyPairSync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: { type: 'spki', format: 'jwk' },
                privateKeyEncoding: { type: 'pkcs8', format: 'jwk' }
            });
            req.session.dpopKey = privateKey;
            uiLog(req, "DPoP", "Generated Ephemeral Client Key", { kty: "RSA", use: "Proof of Possession" });
        } else {
            uiLog(req, "DPoP", "Skipping Key Gen (Bearer Mode Enabled)");
        }

        // 2. Prepare PAR
        const code_verifier = generators.codeVerifier();
        req.session.code_verifier = code_verifier;
        req.session.nonce = generators.nonce();
        req.session.state = generators.state();

        const rar = [{ "type": "account_information", "actions": ["list_accounts"], "locations": [] }];
        const parPayload = {
            authorization_details: JSON.stringify(rar),
            scope: 'openid',
            code_challenge: generators.codeChallenge(code_verifier),
            code_challenge_method: 'S256',
            response_type: 'code',
            redirect_uri: CONFIG.redirect_uri,
            nonce: req.session.nonce,
            state: req.session.state
        };
        
        uiLog(req, "PAR", "Pushing Authorization Request...", null, `Client->>Verify: 2. POST /par`);

        const pushedResponse = await client.pushedAuthorizationRequest(parPayload);
        
        uiLog(req, "PAR", "Received Request URI", pushedResponse, `Verify-->>Client: 3. Return 'request_uri'`);

        req.session.save(() => {
            res.redirect(client.authorizationUrl({ request_uri: pushedResponse.request_uri }));
        });

    } catch (err) {
        console.error(err);
        res.status(500).send("Login Failed: " + err.message);
    }
});

// --- CALLBACK ---
app.get('/callback', async (req, res) => {
    try {
        await init();
        const params = client.callbackParams(req);
        
        uiLog(req, "CALLBACK", "User returned with Auth Code", params, `Verify->>Client: 4. Redirect w/ Code`);

        let extras = {};
        
        // DPoP: Only attach key if enabled
        if (CONFIG.enable_dpop) {
             if (!req.session.dpopKey) throw new Error("Session Lost. Please restart.");
             const dpopKey = createPrivateKey({ key: req.session.dpopKey, format: 'jwk' });
             extras.DPoP = dpopKey;
             uiLog(req, "TOKEN", "Exchanging Code (DPoP Signed)", null, `Client->>Verify: 5. POST /token (Signed)`);
        } else {
             uiLog(req, "TOKEN", "Exchanging Code (Bearer Mode)", null, `Client->>Verify: 5. POST /token (Bearer)`);
        }

        const tokenSet = await client.callback(
            CONFIG.redirect_uri, 
            params, 
            { 
                code_verifier: req.session.code_verifier, 
                nonce: req.session.nonce, 
                state: req.session.state 
            },
            extras // Pass DPoP key or nothing
        );

        req.session.accessToken = tokenSet.access_token;
        req.session.decodedToken = decodeJwt(tokenSet.access_token);
        
        uiLog(req, "TOKEN", "Access Token Acquired", null, `Verify-->>Client: 6. Access Token`);

        req.session.save(() => res.redirect('/dashboard'));

    } catch (err) {
        res.status(500).send("Callback Failed: " + err.message);
    }
});

// --- DASHBOARD UI ---
app.get('/dashboard', (req, res) => {
    if (!req.session.accessToken) return res.redirect('/login');

    const logsHtml = (req.session.logs || []).map(l => `
        <div class="log-entry">
            <div class="log-header">
                <span class="time">${l.time}</span>
                <span class="step">${l.step}</span>
                <span class="msg">${l.message}</span>
            </div>
            ${l.data ? `<details><summary>View Payload</summary><pre>${l.data}</pre></details>` : ''}
        </div>
    `).join('');

    const diagramSteps = (req.session.diagram || []).join('\n    ');
    const mermaidDefinition = `
sequenceDiagram
    participant Client as 💻 Client App
    participant Verify as 🛡️ IBM Verify
    participant Bank as 🏦 Bank API
    ${diagramSteps}
    `;

    // Visual Indicator for Mode
    const modeBadge = CONFIG.enable_dpop 
        ? `<span style="background:green; color:white; padding:4px 8px; border-radius:4px;">🔐 DPoP Enabled</span>`
        : `<span style="background:orange; color:black; padding:4px 8px; border-radius:4px;">🔓 Bearer Token (Legacy)</span>`;

    res.send(`
        <html>
        <head>
            <title>FAPI Live View</title>
            <script type="module">
                import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
                mermaid.initialize({ startOnLoad: true, theme: 'dark', securityLevel: 'loose' });
            </script>
            <style>
                body { font-family: 'Segoe UI', monospace; background: #0d1117; color: #c9d1d9; padding: 0; margin: 0; display: flex; height: 100vh; }
                .sidebar { width: 35%; border-right: 1px solid #30363d; overflow-y: auto; padding: 20px; background: #161b22; }
                .main { width: 65%; padding: 20px; overflow-y: auto; display: flex; flex-direction: column; align-items: center; }
                h1 { color: #58a6ff; font-size: 1.2rem; margin-top: 0; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
                .card { background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 15px; width: 100%; margin-bottom: 20px; }
                .log-entry { margin-bottom: 15px; font-size: 0.9em; border-left: 2px solid #30363d; padding-left: 10px; }
                .step { color: #58a6ff; font-weight: bold; }
                .time { color: #8b949e; font-size: 0.8em; margin-right: 8px; }
                details { margin-top: 5px; }
                pre { background: #0d1117; padding: 8px; border-radius: 4px; overflow-x: auto; color: #7ee787; font-size: 0.85em; }
                .btn { display: block; width: 100%; background: #238636; color: white; padding: 12px; text-align: center; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 1rem; margin-top: 20px; }
                .btn:hover { background: #2ea043; }
                .mermaid { width: 100%; text-align: center; }
            </style>
        </head>
        <body>
            <div class="sidebar">
                <h1>📜 Execution Log</h1>
                <div style="margin-bottom:15px">${modeBadge}</div>
                ${logsHtml}
                <div class="card" style="margin-top: 20px; border-color: #d29922;">
                    <h3 style="color: #d29922; margin-top: 0;">Ready to Access API?</h3>
                    <a href="/fetch-data" class="btn">▶ Execute API Call</a>
                </div>
            </div>
            <div class="main">
                <h1 style="width: 100%">Visual Flow (Animated)</h1>
                <div class="card"><div class="mermaid">${mermaidDefinition}</div></div>
                <div class="card">
                     <h3>🔐 Token Inspector</h3>
                     <p style="color: #8b949e; font-size: 0.9em;">Thumbprint (cnf): <code>${req.session.decodedToken?.cnf?.jkt ? req.session.decodedToken.cnf.jkt.substring(0,10)+'...' : 'None (Bearer)'}</code></p>
                     <pre>${JSON.stringify(req.session.decodedToken, null, 2)}</pre>
                </div>
            </div>
        </body>
        </html>
    `);
});

// --- API CALL ---
app.get('/fetch-data', async (req, res) => {
    try {
        // DPoP Logic (Conditional)
        let requestOptions = { method: 'GET' };
        let curlCommand = "";

        if (CONFIG.enable_dpop) {
            if (!req.session.dpopKey) return res.redirect('/login');
            const dpopKey = createPrivateKey({ key: req.session.dpopKey, format: 'jwk' });
            requestOptions.DPoP = dpopKey;

            uiLog(req, "API", "Calling Bank API (DPoP Signed)...", null, `Client->>Bank: 7. GET /accounts (DPoP)`);

            // Fake Curl
            const jwk = await exportJWK(dpopKey);
            const dpopProof = await new SignJWT({ htu: CONFIG.resource_url, htm: 'GET', jti: generators.nonce() })
                .setProtectedHeader({ alg: 'PS256', typ: 'dpop+jwt', jwk: jwk }).setIssuedAt().sign(dpopKey);
            curlCommand = `curl -v -X GET ${CONFIG.resource_url} \\\n  -H "Authorization: DPoP ${req.session.accessToken}" \\\n  -H "DPoP: ${dpopProof}"`;
        } else {
            // Bearer Logic
            uiLog(req, "API", "Calling Bank API (Bearer Token)...", null, `Client->>Bank: 7. GET /accounts (Bearer)`);
            curlCommand = `curl -v -X GET ${CONFIG.resource_url} \\\n  -H "Authorization: Bearer ${req.session.accessToken}"`;
        }

        console.log("\n🛑 SECURITY CHECK: Curl Command Used:");
        console.log(curlCommand + "\n");
        uiLog(req, "SECURITY", "Logged CURL to Console", { curl: curlCommand });

        // Execute
        const response = await client.requestResource(
            CONFIG.resource_url,
            req.session.accessToken,
            requestOptions
        );

        const data = JSON.parse(response.body.toString());
        uiLog(req, "API", `Received ${data.length} Accounts`, data, `Bank-->>Client: 8. JSON Data`);
        req.session.save(() => res.redirect('/dashboard'));

    } catch (err) {
        uiLog(req, "API Error", err.message, null, `Bank--xClient: Error ${err.message}`);
        req.session.save(() => res.redirect('/dashboard'));
    }
});

app.listen(3000, () => console.log(`\n🌐 Client UI running on http://localhost:3000`));
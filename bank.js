require('dotenv').config(); 
const express = require('express');
const bodyParser = require('body-parser');
const { jwtVerify, createRemoteJWKSet, importJWK, decodeProtectedHeader } = require('jose');
const app = express();

app.use(bodyParser.json());

// =============================================================================
// 1. CONFIGURATION
// =============================================================================
const TENANT_URL = process.env.VERIFY_TENANT_URL ? process.env.VERIFY_TENANT_URL.replace(/\/$/, "") : null;
const AUDIENCE = process.env.API_AUDIENCE;

// Read DPoP Toggle Flag
const ENABLE_DPOP = process.env.ENABLE_DPOP === 'true';

if (!TENANT_URL || !AUDIENCE) {
    console.error("❌ ERROR: Missing .env variables.");
    process.exit(1);
}

// =============================================================================
// 2. DISCOVERY
// =============================================================================
const DISCOVERY_URL = `${TENANT_URL}/oauth2/.well-known/openid-configuration`;
let JWKS;

async function getJWKS() {
    if (JWKS) return JWKS;
    console.log("   🔎 connecting to Discovery Endpoint...");
    const response = await fetch(DISCOVERY_URL);
    const config = await response.json();
    JWKS = createRemoteJWKSet(new URL(config.jwks_uri));
    return JWKS;
}

// =============================================================================
// 3. MOCK DATA (Restored 3 Accounts)
// =============================================================================
const ACCOUNTS_DB = {
    "user_123": [
        { id: "ACC-001", name: "Savings Account", balance: 5000 },
        { id: "ACC-002", name: "Checking Account", balance: 250 },
        { id: "ACC-003", name: "Home Mortgage", balance: -200000 } // <--- RESTORED
    ]
};

// =============================================================================
// 4. SECURITY MIDDLEWARE (PEP)
// =============================================================================
const validateToken = async (req, res, next) => {
    console.log(`\n📥 INCOMING REQUEST to ${req.path}`);
    console.log(`   ⚙️  Security Mode: ${ENABLE_DPOP ? '🔐 Strict DPoP' : '🔓 Standard Bearer'}`);
    
    const authHeader = req.headers.authorization;
    const dpopHeader = req.headers.dpop;

    try {
        if (!authHeader) throw new Error('Missing Authorization Header');

        // Toggle Check
        if (ENABLE_DPOP) {
            if (!authHeader.startsWith('DPoP ')) {
                throw new Error('Invalid Token Type. Expected DPoP, got Bearer.');
            }
            if (!dpopHeader) {
                throw new Error('Missing DPoP Proof Header');
            }
        }

        const token = authHeader.split(' ')[1];

        // Step 1: Validate Access Token
        console.log("   🛡️  Step 1: Validating Access Token...");
        const header = decodeProtectedHeader(token);
        const jwks = await getJWKS();
        
        const { payload } = await jwtVerify(token, jwks, { 
            audience: AUDIENCE,
            typ: header.typ 
        });
        
        console.log("   ✅ Access Token Valid. User:", payload.sub);
        req.user = payload;

        // Step 2: Validate DPoP Proof (Conditional)
        if (ENABLE_DPOP) {
            console.log("   🛡️  Step 2: Validating DPoP Proof...");
            const dpopHeaderDecoded = JSON.parse(Buffer.from(dpopHeader.split('.')[0], 'base64url').toString());
            const alg = dpopHeaderDecoded.alg || 'ES256';
            const dpopKey = await importJWK(dpopHeaderDecoded.jwk, alg);
            
            await jwtVerify(dpopHeader, dpopKey, { 
                typ: 'dpop+jwt', 
                algorithms: ['ES256', 'PS256', 'RS256'] 
            });
            console.log("   ✅ DPoP Proof Valid.");
        } else {
            console.log("   ⚠️  Step 2: Skipped (Bearer Mode Active).");
        }

        next();

    } catch (err) {
        console.error("   ⛔ BLOCKED:", err.message);
        res.status(401).json({ error: "Unauthorized", details: err.message });
    }
};

app.get('/accounts', validateToken, (req, res) => {
    console.log(`   🚀 Releasing ${ACCOUNTS_DB["user_123"].length} accounts to Client`);
    res.json(ACCOUNTS_DB["user_123"]);
});

// Consent Webhook
app.get('/webhook/consent-options', (req, res) => {
    res.json({
        accounts: ACCOUNTS_DB["user_123"].map(a => ({ 
            id: a.id, 
            description: `${a.name} (...${a.id.slice(-3)})` 
        }))
    });
});

app.listen(8080, () => console.log(`🚀 Bank API running on port 8080`));
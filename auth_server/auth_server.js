import express from 'express';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import crypto from 'crypto';
import os from 'os';

function getLocalIpAddress() {
  const interfaces = os.networkInterfaces();
  let fallbackIp = 'localhost';
  
  const keys = Object.keys(interfaces).sort((a, b) => {
    const aLower = a.toLowerCase();
    const bLower = b.toLowerCase();
    
    const priority = (name) => {
      if (name.includes('ethernet') && !name.includes('vethernet')) return 3;
      if (name.includes('wi-fi') || name.includes('wlan')) return 3;
      if (name.startsWith('eth') || name.startsWith('wlan') || name.startsWith('en')) return 2;
      return 1;
    };
    
    return priority(bLower) - priority(aLower);
  });

  for (const name of keys) {
    const nameLower = name.toLowerCase();
    
    if (
      nameLower.includes('nord') ||
      nameLower.includes('vpn') ||
      nameLower.includes('wsl') ||
      nameLower.includes('virtual') ||
      nameLower.includes('veth') ||
      nameLower.includes('docker') ||
      nameLower.includes('host-only') ||
      nameLower.includes('loopback')
    ) {
      continue;
    }

    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        if (iface.address.startsWith('192.168.')) {
          return iface.address;
        }
        if (fallbackIp === 'localhost') {
          fallbackIp = iface.address;
        }
      }
    }
  }
  return fallbackIp;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Serve the static verify.html from public
app.use(express.static(path.join(__dirname, 'public')));

const PORT = 3001;
const DASHBOARD_URL = 'http://localhost:3000';

// Load Manufacturer Public Key (CA Certificate)
const pubKeyPath = path.join(__dirname, 'manufacturer_pubkey.pem');
if (!fs.existsSync(pubKeyPath)) {
  console.error('❌ Error: manufacturer_pubkey.pem not found. Run provision.js first.');
  process.exit(1);
}
const manufacturerPubKey = crypto.createPublicKey(fs.readFileSync(pubKeyPath, 'utf8'));

// In-memory OAuth 2.0 State
const activeAuthorizations = new Map(); // device_code -> auth details
const userCodeMap = new Map();         // user_code -> device_code
const issuedTokens = new Map();        // access_token -> token details (client_id, scope, user)

// Helper to send logs to the Dashboard server so they appear in the UI console
async function logToDashboard(type, message, details = null) {
  try {
    const response = await fetch(`${DASHBOARD_URL}/api/logs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source: 'Server Auth',
        type,
        message,
        details
      })
    });
    if (!response.ok) {
      console.error('[AS] Failed to send log to Dashboard:', response.statusText);
    }
  } catch (err) {
    console.log(`[AS][${type.toUpperCase()}] ${message}`);
  }
}

// Endpoint de salud
app.get('/health', (req, res) => {
  res.json({ status: 'online', service: 'auth-server' });
});

/**
 * 1. Device Authorization Request (RFC 8628 Section 3.1)
 */
app.post('/auth/device_authorize', async (req, res) => {
  const { client_id, timestamp, signature, attestation_certificate } = req.body || {};

  if (!client_id || !attestation_certificate) {
    return res.status(400).json({ error: 'invalid_request', message: 'Faltan parámetros requeridos.' });
  }

  await logToDashboard('REQ_REC', `Recibida solicitud de autorización de dispositivo para: ${client_id}`);

  try {
    // Verify the Device Attestation Certificate using the Manufacturer Public Key
    const certObj = JSON.parse(attestation_certificate);
    const certData = certObj.device_id + ":" + certObj.device_pubkey;
    
    const isCertValid = crypto.verify(
      'sha256',
      Buffer.from(certData),
      manufacturerPubKey,
      Buffer.from(certObj.manufacturer_signature, 'hex')
    );

    if (!isCertValid) {
      await logToDashboard('ERROR', `❌ ATESTACIÓN FALLIDA: El certificado del dispositivo no está firmado por un fabricante autorizado.`);
      return res.status(400).json({ error: 'invalid_attestation_certificate' });
    }

    await logToDashboard('CRYPT', `✅ Atestación del fabricante verificada correctamente.`);

    // Verify request signature using the Device Public Key from the certificate
    const devicePubKey = crypto.createPublicKey(certObj.device_pubkey);
    const payloadToVerify = client_id + ":" + timestamp;
    
    const isSignatureValid = crypto.verify(
      'sha256',
      Buffer.from(payloadToVerify),
      devicePubKey,
      Buffer.from(signature, 'hex')
    );

    if (!isSignatureValid) {
      await logToDashboard('ERROR', `❌ FIRMA INVÁLIDA: La firma de la petición no coincide con la clave del dispositivo.`);
      return res.status(400).json({ error: 'invalid_signature' });
    }

    await logToDashboard('CRYPT', `✅ Firma de petición verificada con la clave pública del dispositivo.`);

    // Generate OAuth codes (RFC 8628 Section 3.2)
    const device_code = 'dev_' + crypto.randomBytes(16).toString('hex');
    const user_code = crypto.randomBytes(4).toString('hex').toUpperCase().match(/.{1,4}/g).join('-');
    const localIp = getLocalIpAddress();
    const verification_uri = `http://${localIp}:${PORT}/verify.html`;
    const expires_in = 300; // 5 minutes

    const authData = {
      device_code,
      user_code,
      client_id,
      status: 'pending',
      expires_at: Date.now() + (expires_in * 1000),
      access_token: null
    };

    activeAuthorizations.set(device_code, authData);
    userCodeMap.set(user_code, device_code);

    await logToDashboard('SUCCESS', `Códigos generados: Código de Usuario: ${user_code} (Expira en 5 min)`);

    res.json({
      device_code,
      user_code,
      verification_uri,
      verification_uri_complete: `${verification_uri}?code=${user_code}`,
      expires_in,
      interval: 5
    });

  } catch (err) {
    await logToDashboard('ERROR', `Error en la atestación: ${err.message}`);
    res.status(500).json({ error: 'server_error', message: err.message });
  }
});

/**
 * 2. Token Endpoint (RFC 8628 Section 3.4 & 3.5)
 */
app.post('/auth/token', async (req, res) => {
  const { device_code, grant_type } = req.body;

  if (grant_type !== 'urn:ietf:params:oauth:grant-type:device_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  const authData = activeAuthorizations.get(device_code);

  if (!authData) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  if (Date.now() > authData.expires_at) {
    activeAuthorizations.delete(device_code);
    userCodeMap.forEach((v, k) => {
      if (v === device_code) userCodeMap.delete(k);
    });
    await logToDashboard('ERROR', `Intento de polling pero el código ha expirado para el cliente: ${authData.client_id}`);
    return res.status(400).json({ error: 'expired_token' });
  }

  if (authData.status === 'pending') {
    return res.status(400).json({ error: 'authorization_pending' });
  }

  if (authData.status === 'approved') {
    const access_token = 'tok_' + crypto.randomBytes(24).toString('hex');
    
    // Save the token with its metadata
    issuedTokens.set(access_token, {
      client_id: authData.client_id,
      expires_at: Date.now() + 3600 * 1000
    });
    
    authData.access_token = access_token;
    authData.status = 'issued';

    await logToDashboard('SUCCESS', `🔑 Token de acceso emitido con éxito para: ${authData.client_id}`);

    return res.json({
      access_token,
      token_type: 'Bearer',
      expires_in: 3600
    });
  }

  return res.status(400).json({ error: 'invalid_grant' });
});

/**
 * 3. User Consent/Verification Endpoint
 */
app.post('/auth/verify', async (req, res) => {
  const { user_code } = req.body;
  const device_code = userCodeMap.get(user_code);
  const authData = activeAuthorizations.get(device_code);

  if (!authData) {
    return res.status(400).json({ error: 'invalid_user_code', message: 'El código introducido es incorrecto o ha expirado.' });
  }

  if (Date.now() > authData.expires_at) {
    return res.status(400).json({ error: 'expired_code', message: 'El código ha expirado. Por favor, reinicia el registro.' });
  }

  authData.status = 'approved';
  
  await logToDashboard('SUCCESS', `👤 Usuario aprobó el código: ${user_code}. Acceso concedido.`);

  // Inform Dashboard to update device state visually
  try {
    await fetch(`${DASHBOARD_URL}/api/device/authorized`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_code })
    });
  } catch (e) {
    // Ignore dashboard notification errors
  }

  res.json({ message: '¡Dispositivo autorizado correctamente! Ya puedes mirar la pantalla de tu portarretratos.' });
});

/**
 * 4. Token Introspection / Validation API (For Resource Server)
 */
app.post('/auth/validate_token', (req, res) => {
  const { access_token } = req.body;

  if (!access_token) {
    return res.status(400).json({ active: false, error: 'missing_token' });
  }

  const tokenData = issuedTokens.get(access_token);

  if (!tokenData) {
    return res.json({ active: false });
  }

  if (Date.now() > tokenData.expires_at) {
    issuedTokens.delete(access_token);
    return res.json({ active: false, error: 'expired_token' });
  }

  return res.json({
    active: true,
    client_id: tokenData.client_id,
    scope: 'read:photos'
  });
});

app.listen(PORT, () => {
  const localIp = getLocalIpAddress();
  console.log(`🔑 [Auth Server] Running on http://localhost:${PORT}`);
  console.log(`👉 Verification Page: http://${localIp}:${PORT}/verify.html`);
});

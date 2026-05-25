import express from 'express';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import crypto from 'crypto';
import { WebSocketServer, WebSocket } from 'ws';
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

// Parseo estándar de JSON (el dispositivo envía Content-Type: application/json)
app.use(express.json());

// Servir archivos estáticos del frontend
app.use(express.static(path.join(__dirname, 'public')));

const PORT = 3000;

// ==========================================================================
// CRIPTOGRAFÍA DE ATESTACIÓN (FABRICANTE)
// ==========================================================================
// Para simular la atestación de hardware de fábrica, compartimos un par de claves
// del "Fabricante" (Manufacturer CA) a través de un archivo local.
const keysFile = path.join(__dirname, 'manufacturer_keys.json');
let manufacturerPrivKey, manufacturerPubKey;

if (fs.existsSync(keysFile)) {
  const keys = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
  manufacturerPrivKey = crypto.createPrivateKey(keys.privateKey);
  manufacturerPubKey = crypto.createPublicKey(keys.publicKey);
} else {
  const keyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  manufacturerPrivKey = keyPair.privateKey;
  manufacturerPubKey = keyPair.publicKey;
  fs.writeFileSync(keysFile, JSON.stringify({
    privateKey: manufacturerPrivKey.export({ type: 'pkcs1', format: 'pem' }),
    publicKey: manufacturerPubKey.export({ type: 'pkcs1', format: 'pem' })
  }, null, 2));
}


// ==========================================================================
// ALMACENAMIENTO EN MEMORIA (OAUTH 2.0 STATE)
// ==========================================================================
const activeAuthorizations = new Map(); // device_code -> authorization details
const userCodeMap = new Map();         // user_code -> device_code
const issuedTokens = new Set();        // access_token list

// WebSocket clients
const wsClients = new Set();

function broadcastToUI(event, data) {
  const payload = JSON.stringify({ event, data });
  for (const client of wsClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
}

// ==========================================================================
// ENDPOINTS OAUTH 2.0 - CERTIFICACIÓN Y FLUJO DE DISPOSITIVO (AS)
// ==========================================================================

// Endpoint de salud del servidor (para el panel de control)
app.get('/health', (req, res) => {
  res.json({ status: 'online' });
});

/**
 * 1. Solicitud de Autorización de Dispositivo (RFC 8628 Section 3.1)
 * Recibe client_id, timestamp, firma de la petición y el certificado de atestación del dispositivo.
 */
app.post('/auth/device_authorize', (req, res) => {
  const { client_id, timestamp, signature, attestation_certificate } = req.body || {};

  // Guard: cuerpo vacío (p.ej. ping de status o petición mal formada)
  if (!client_id || !attestation_certificate) {
    return res.status(400).json({ error: 'invalid_request', message: 'Faltan parámetros requeridos.' });
  }

  broadcastToUI('log', {
    source: 'Server Auth',
    type: 'REQ_REC',
    message: `Petición CoAP/HTTP recibida en /auth/device_authorize para el dispositivo: ${client_id}`
  });

  try {
    // Atestación Paso 1: Verificar el certificado del dispositivo con la clave pública del fabricante
    const certObj = JSON.parse(attestation_certificate);
    const certData = certObj.device_id + ":" + certObj.device_pubkey;
    
    const isCertValid = crypto.verify(
      'sha256',
      Buffer.from(certData),
      manufacturerPubKey,
      Buffer.from(certObj.manufacturer_signature, 'hex')
    );

    if (!isCertValid) {
      broadcastToUI('log', {
        source: 'Server Auth',
        type: 'ERROR',
        message: `❌ ATESTACIÓN FALLIDA: El certificado del dispositivo no está firmado por un fabricante autorizado.`
      });
      return res.status(400).json({ error: 'invalid_attestation_certificate' });
    }

    broadcastToUI('log', {
      source: 'Server Auth',
      type: 'CRYPT',
      message: `✅ Atestación de fábrica verificada correctamente.`
    });

    // Atestación Paso 2: Verificar la firma de la petición usando la clave pública del dispositivo extraída del certificado
    const devicePubKey = crypto.createPublicKey(certObj.device_pubkey);
    const payloadToVerify = client_id + ":" + timestamp;
    
    const isSignatureValid = crypto.verify(
      'sha256',
      Buffer.from(payloadToVerify),
      devicePubKey,
      Buffer.from(signature, 'hex')
    );

    if (!isSignatureValid) {
      broadcastToUI('log', {
        source: 'Server Auth',
        type: 'ERROR',
        message: `❌ FIRMA INVÁLIDA: La firma de la petición no coincide con la clave pública del dispositivo.`
      });
      return res.status(400).json({ error: 'invalid_signature' });
    }

    broadcastToUI('log', {
      source: 'Server Auth',
      type: 'CRYPT',
      message: `✅ Firma de petición del dispositivo verificada. Identidad del hardware confirmada.`
    });

    // Generar códigos para OAuth 2.0 Device Flow (RFC 8628 Section 3.2)
    const device_code = 'dev_' + crypto.randomBytes(16).toString('hex');
    // Código de usuario legible (Ej: ABCD-1234)
    const user_code = crypto.randomBytes(4).toString('hex').toUpperCase().match(/.{1,4}/g).join('-');
    const localIp = getLocalIpAddress();
    const verification_uri = `http://${localIp}:${PORT}/verify.html`;
    const expires_in = 300; // 5 minutos

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

    broadcastToUI('log', {
      source: 'Server Auth',
      type: 'SUCCESS',
      message: `Generados códigos OAuth: Código de Usuario: ${user_code} (Expira en 5 min)`
    });

    // Respuesta estándar de Autorización de Dispositivo (RFC 8628 Section 3.2)
    res.json({
      device_code,
      user_code,
      verification_uri,
      verification_uri_complete: `${verification_uri}?code=${user_code}`,
      expires_in,
      interval: 5 // poll interval en segundos
    });

  } catch (err) {
    broadcastToUI('log', {
      source: 'Server Auth',
      type: 'ERROR',
      message: `Error procesando la atestación: ${err.message}`
    });
    res.status(500).json({ error: 'server_error', message: err.message });
  }
});

/**
 * 2. Endpoint de Emisión de Tokens (RFC 8628 Section 3.4 & 3.5)
 * El dispositivo realiza polling enviando su device_code.
 */
app.post('/auth/token', (req, res) => {
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
    broadcastToUI('log', {
      source: 'Server Auth',
      type: 'ERROR',
      message: `Dispositivo ${authData.client_id} intentó polling pero el código ha expirado.`
    });
    return res.status(400).json({ error: 'expired_token' });
  }

  if (authData.status === 'pending') {
    // Si aún no está autorizado, retorna error 400 con authorization_pending (RFC 8628 Section 3.5)
    return res.status(400).json({ error: 'authorization_pending' });
  }

  if (authData.status === 'approved') {
    // Generar access_token único
    const access_token = 'tok_' + crypto.randomBytes(24).toString('hex');
    issuedTokens.add(access_token);
    
    // Guardamos la asociación en el estado de autenticación
    authData.access_token = access_token;
    authData.status = 'issued';

    broadcastToUI('log', {
      source: 'Server Auth',
      type: 'SUCCESS',
      message: `🔑 Token emitido con éxito para dispositivo: ${authData.client_id}`
    });

    // Respuesta del token exitosa (RFC 6749 Section 5.1)
    return res.json({
      access_token,
      token_type: 'Bearer',
      expires_in: 3600
    });
  }

  return res.status(400).json({ error: 'invalid_grant' });
});

/**
 * 3. Endpoint de Consentimiento/Validación del Usuario (Vista B)
 * Recibe el user_code ingresado por el usuario en verify.html y autoriza el dispositivo.
 */
app.post('/auth/verify', (req, res) => {
  const { user_code } = req.body;
  const device_code = userCodeMap.get(user_code);
  const authData = activeAuthorizations.get(device_code);

  if (!authData) {
    return res.status(400).json({ error: 'invalid_user_code', message: 'El código introducido es incorrecto o ha expirado.' });
  }

  if (Date.now() > authData.expires_at) {
    return res.status(400).json({ error: 'expired_code', message: 'El código ha expirado. Por favor, reinicia el registro en la tablet.' });
  }

  // Cambiar estado a aprobado para que el siguiente poll del dispositivo reciba el token
  authData.status = 'approved';
  
  broadcastToUI('log', {
    source: 'Server Auth',
    type: 'SUCCESS',
    message: `👤 Usuario aprobó el código: ${user_code}. Acceso concedido.`
  });

  // Notificar al dispositivo via WebSocket para sincronización rápida
  broadcastToUI('device_authorized', { device_code });

  res.json({ message: '¡Dispositivo autorizado correctamente! Ya puedes mirar la pantalla de tu portarretratos.' });
});

// ==========================================================================
// SERVIDOR DE RECURSOS (PROTEGIDO POR OAUTH TOKEN) (RS)
// ==========================================================================

// Middleware para verificar la validez del token
function authenticateToken(req, res, next) {
  // Acepta token en cabeceras HTTP estándar o en el cuerpo de la petición (POST) para compatibilidad con el Proxy CoAP
  let token = null;
  const authHeader = req.headers['authorization'];
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (req.body && req.body.access_token) {
    token = req.body.access_token;
  }

  if (!token) {
    broadcastToUI('log', {
      source: 'Resource Server',
      type: 'ERROR',
      message: `Acceso denegado: Petición sin token de acceso.`
    });
    return res.status(401).json({ error: 'access_denied', message: 'Missing token' });
  }

  if (!issuedTokens.has(token)) {
    broadcastToUI('log', {
      source: 'Resource Server',
      type: 'ERROR',
      message: `Acceso denegado: Token inválido o revocado.`
    });
    return res.status(403).json({ error: 'invalid_token', message: 'Invalid token' });
  }

  next();
}

/**
 * 1. GET/POST /api/photos: Retorna la lista de recursos (fotos) disponibles
 */
app.all('/api/photos', authenticateToken, (req, res) => {
  broadcastToUI('log', {
    source: 'Resource Server',
    type: 'SUCCESS',
    message: `Petición autorizada. Devolviendo catálogo de imágenes.`
  });

  const photoList = [
    { id: 1, name: 'Smart City Landscape', url: '/api/photos/1' },
    { id: 2, name: 'IoT Node Hardware', url: '/api/photos/2' },
    { id: 3, name: 'Control Room Grid', url: '/api/photos/3' },
    { id: 4, name: 'Digital Grid Networks', url: '/api/photos/4' }
  ];

  res.json({ photos: photoList });
});

/**
 * 2. GET/POST /api/photos/:id: Retorna el archivo binario físico de la foto seleccionada
 */
app.all('/api/photos/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const imagePath = path.join(__dirname, 'public', 'images', `foto${id}.png`);

  if (!fs.existsSync(imagePath)) {
    return res.status(404).json({ error: 'photo_not_found' });
  }

  broadcastToUI('log', {
    source: 'Resource Server',
    type: 'SUCCESS',
    message: `Enviando imagen física: foto${id}.png`
  });

  res.sendFile(imagePath);
});

// ==========================================================================
// HTTP SERVER & WEBSOCKET SERVER INTEGRATION
// ==========================================================================
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
  wsClients.add(ws);
  
  ws.on('message', (message) => {
    try {
      const parsed = JSON.parse(message);
      // Reenviar mensajes del dispositivo (logs) al frontend de la UI
      if (parsed.event === 'device_log') {
        broadcastToUI('log', parsed.data);
      }
      if (parsed.event === 'device_state') {
        broadcastToUI('device_state', parsed.data);
      }
      if (parsed.event === 'start_registration') {
        broadcastToUI('start_registration', parsed.data || {});
      }
    } catch (e) {
      // Ignorar mensajes mal formateados
    }
  });

  ws.on('close', () => {
    wsClients.delete(ws);
  });
});

server.listen(PORT, () => {
  const localIp = getLocalIpAddress();
  console.log(`======================================================`);
  console.log(`OAuth 2.0 Device Flow Server running on http://localhost:${PORT}`);
  console.log(`- Panel Principal (Vista A): http://localhost:${PORT}/index.html`);
  console.log(`- Portal Móvil (Vista B) [IP Local]: http://${localIp}:${PORT}/verify.html`);
  console.log(`======================================================`);
});

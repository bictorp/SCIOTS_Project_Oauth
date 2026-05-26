import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocket } from 'ws';
import http from 'http';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Port configurations
const DASHBOARD_WS_URL = 'ws://localhost:3000?role=device';
const AUTH_SERVER_HOST = 'localhost';
const AUTH_SERVER_PORT = 3001;
const RESOURCE_SERVER_HOST = 'localhost';
const RESOURCE_SERVER_PORT = 3002;

let ws = null;
let devicePrivateKey = null;
let deviceId = null;
let attestationCert = null;
let wsReconnectDelay = 1000;

// Load pre-provisioned credentials
const credsPath = path.join(__dirname, 'device_credentials.json');
if (!fs.existsSync(credsPath)) {
  console.error('❌ Error: device_credentials.json not found. Run provision.js first.');
  process.exit(1);
}

try {
  const credentials = JSON.parse(fs.readFileSync(credsPath, 'utf8'));
  deviceId = credentials.device_id;
  devicePrivateKey = crypto.createPrivateKey(credentials.device_private_key);
  attestationCert = credentials.attestation_certificate;
  console.log(`🔑 Pre-provisioned device credentials loaded for: ${deviceId}`);
} catch (e) {
  console.error('❌ Error loading device credentials:', e.message);
  process.exit(1);
}

// WebSocket connection to Dashboard Server (for streaming logs and receiving events)
function connectWebSocket() {
  ws = new WebSocket(DASHBOARD_WS_URL);

  ws.on('open', () => {
    wsReconnectDelay = 1000;
    sendUILog('system', '📡 Conexión WebSocket establecida con el Servidor de Control.');
    updateUIState('OFFLINE', { message: 'Dispositivo en espera. Pulsa "Encender y Registrar".' });
  });

  ws.on('message', (message) => {
    try {
      const { event, data } = JSON.parse(message);
      if (event === 'start_registration') {
        startDeviceRegistration();
      }
    } catch (e) {
      console.error('[Device] Error procesando comando WS:', e.message);
    }
  });

  ws.on('close', () => {
    console.log(`[Device] WS desconectado. Reintentando en ${wsReconnectDelay}ms...`);
    setTimeout(connectWebSocket, wsReconnectDelay);
    wsReconnectDelay = Math.min(wsReconnectDelay * 2, 15000);
  });
}

function sendUILog(type, message, details = null) {
  const payload = JSON.stringify({
    event: 'device_log',
    data: { source: 'Dispositivo IoT', type, message, details }
  });
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(payload);
  }
  console.log(`[Device][${type.toUpperCase()}] ${message}`);
}

function updateUIState(state, details) {
  const payload = JSON.stringify({ event: 'device_state', data: { state, details } });
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(payload);
  }
}

/**
 * Generic HTTP POST requester
 */
function httpPost(host, port, pathname, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);

    const options = {
      hostname: host,
      port:     port,
      path:     pathname,
      method:   'POST',
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-CoAP-Proxy':  'true',
        'X-CoAP-Device': deviceId
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// OAuth 2.0 Device Flow execution
async function startDeviceRegistration() {
  sendUILog('start', '🔌 Encendiendo dispositivo e iniciando registro seguro...');
  updateUIState('REGISTERING', { message: 'Inicializando criptografía RSA...' });

  try {
    // ── PASO 1: Firmar la petición usando la clave privada ya provista en el enclave ──
    const timestamp      = Date.now().toString();
    const payloadToSign  = `${deviceId}:${timestamp}`;
    sendUILog('crypt', '✍️  Firmando petición con la clave privada de hardware del dispositivo...');
    const signature = crypto.sign('sha256', Buffer.from(payloadToSign), devicePrivateKey);

    // ── PASO 2: Enviar solicitud de autorización con el certificado de atestación ──
    sendUILog('req', `📤 Enviando CoAP POST → HTTP al AS (Puerto 3001) /auth/device_authorize...`, {
      device_id: deviceId,
      timestamp
    });

    const authResponse = await httpPost(AUTH_SERVER_HOST, AUTH_SERVER_PORT, '/auth/device_authorize', {
      client_id:               deviceId,
      timestamp,
      signature:               signature.toString('hex'),
      attestation_certificate: JSON.stringify(attestationCert)
    });

    if (authResponse.status !== 200) {
      throw new Error(`El Servidor de Autorización rechazó la atestación: ${JSON.stringify(authResponse.data)}`);
    }

    const authData = authResponse.data;
    sendUILog('res', `✅ Registro aceptado. Código de usuario: ${authData.user_code}`, authData);

    updateUIState('PENDING_USER', {
      user_code:        authData.user_code,
      verification_uri: authData.verification_uri_complete,
      expires_in:       authData.expires_in
    });

    // ── PASO 3: Iniciar polling de tokens ──
    startTokenPolling(authData.device_code, authData.interval);

  } catch (err) {
    sendUILog('error', `❌ Error en el registro: ${err.message}`);
    updateUIState('ERROR', { error: err.message });
  }
}

function startTokenPolling(device_code, interval) {
  let attempt = 0;

  const pollTimer = setInterval(async () => {
    attempt++;
    sendUILog('req', `🔄 Polling de tokens — Intento ${attempt} vía POST /auth/token en AS...`);

    try {
      const response = await httpPost(AUTH_SERVER_HOST, AUTH_SERVER_PORT, '/auth/token', {
        device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
      });

      if (response.status !== 200) {
        const error = response.data.error;
        if (error === 'authorization_pending') {
          sendUILog('res', `⏳ Esperando autorización del usuario... (intento ${attempt})`);
        } else {
          sendUILog('error', `❌ Error de polling: ${error}`);
          clearInterval(pollTimer);
          updateUIState('ERROR', { error });
        }
        return;
      }

      const tokenData = response.data;
      sendUILog('res', `🔑 ¡Token de acceso emitido con éxito!`);
      clearInterval(pollTimer);

      downloadPhotos(tokenData.access_token);

    } catch (err) {
      sendUILog('error', `❌ Error de red durante el polling: ${err.message}`);
      clearInterval(pollTimer);
      updateUIState('ERROR', { error: err.message });
    }
  }, interval * 1000);
}

async function downloadPhotos(access_token) {
  sendUILog('req', '📸 Solicitando catálogo de fotos al Servidor de Recursos (Puerto 3002) con token Bearer...');

  try {
    const response = await httpPost(RESOURCE_SERVER_HOST, RESOURCE_SERVER_PORT, '/api/photos', { access_token });

    if (response.status !== 200) {
      throw new Error(`Error del RS: ${JSON.stringify(response.data)}`);
    }

    sendUILog('res', `📷 Catálogo recibido. Total de fotos: ${response.data.photos.length}.`);
    updateUIState('AUTHORIZED', {
      photos:       response.data.photos,
      access_token
    });

  } catch (err) {
    sendUILog('error', `❌ Error al acceder al Servidor de Recursos: ${err.message}`);
    updateUIState('ERROR', { error: err.message });
  }
}

console.log('[Device] Iniciando cliente IoT...');
connectWebSocket();

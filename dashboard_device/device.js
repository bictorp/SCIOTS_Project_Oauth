import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { WebSocket } from 'ws';
import http from 'http';
import coap from 'coap';
import coapPacket from 'coap-packet';

// Incrementar el tamaño máximo de paquete permitido por CoAP para soportar el certificado RSA de atestación
const originalGenerate = coapPacket.generate;
coapPacket.generate = function (packet, maxLength) {
  const limit = (maxLength === 1280 || maxLength === undefined) ? 4096 : maxLength;
  return originalGenerate(packet, limit);
};
coap.parameters.maxMessageSize = 4096;
coap.parameters.maxPayloadSize = 4096;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Port configurations
const DASHBOARD_WS_URL = 'ws://localhost:3000?role=device';

let COAP_PROXY_HOST = '127.0.0.1';
try {
  // En Windows, obtenemos la IP virtual de red de WSL.
  // Esto es necesario porque WSL2 no reenvía paquetes UDP de 'localhost' desde Windows hacia el contenedor Linux.
  const wslIp = execSync('wsl hostname -I').toString().trim().split(' ')[0];
  if (wslIp) {
    COAP_PROXY_HOST = wslIp;
  }
} catch (e) {
  console.log('⚠️ No se pudo detectar la IP de WSL, usando 127.0.0.1');
}

const AUTH_SERVER_HOST = COAP_PROXY_HOST;
const AUTH_SERVER_PORT = 5683; // CoAP Auth Proxy UDP Port
const RESOURCE_SERVER_HOST = COAP_PROXY_HOST;
const RESOURCE_SERVER_PORT = 5685; // CoAP Resource Proxy UDP Port

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

  ws.on('error', (err) => {
    // Evita que la aplicación falle por un evento de error no manejado (Unhandled Exception)
    // El evento 'close' se disparará inmediatamente después e intentará reconectar de forma segura.
    console.log('[Device] Buscando conexión con el Dashboard...');
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
/**
 * Generic CoAP POST requester
 */
function coapPost(host, port, pathname, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);

    const req = coap.request({
      host: host,
      port: port,
      pathname: pathname,
      method: 'POST',
      options: {
        'Content-Format': 'application/json'
      }
    });

    req.on('response', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk.toString(); });
      res.on('end', () => {
        const httpStatus = httpStatusFromCoapCode(res.code);
        try {
          resolve({ status: httpStatus, data: JSON.parse(data) });
        } catch {
          resolve({ status: httpStatus, data });
        }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function httpStatusFromCoapCode(coapCode) {
  if (!coapCode) return 200;
  if (typeof coapCode === 'number') return coapCode;
  
  const codeStr = coapCode.toString();
  if (codeStr === '2.05') return 200;
  if (codeStr === '2.01') return 201;
  if (codeStr === '2.04') return 204;
  if (codeStr === '4.00') return 400;
  if (codeStr === '4.01') return 401;
  if (codeStr === '4.03') return 403;
  if (codeStr === '4.04') return 404;
  if (codeStr === '4.05') return 405;
  if (codeStr === '5.00') return 500;
  if (codeStr === '5.02') return 502;
  if (codeStr === '5.04') return 504;
  
  if (codeStr.startsWith('2.')) return 200;
  if (codeStr.startsWith('4.')) return 400;
  if (codeStr.startsWith('5.')) return 500;
  return 200;
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
    sendUILog('req', `📤 Enviando CoAP POST al Proxy de AS (Puerto 5683) /auth/device_authorize...`, {
      device_id: deviceId,
      timestamp
    });

    const authResponse = await coapPost(AUTH_SERVER_HOST, AUTH_SERVER_PORT, '/auth/device_authorize', {
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
    sendUILog('req', `🔄 Polling de tokens — Intento ${attempt} vía CoAP POST /auth/token en AS (Puerto 5683)...`);

    try {
      const response = await coapPost(AUTH_SERVER_HOST, AUTH_SERVER_PORT, '/auth/token', {
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
  sendUILog('req', '📸 Solicitando catálogo de fotos al Proxy del RS (Puerto 5685) con token Bearer...');

  try {
    const response = await coapPost(RESOURCE_SERVER_HOST, RESOURCE_SERVER_PORT, '/api/photos', { access_token });

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

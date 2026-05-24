/**
 * device.js - Cliente IoT: "Portarretratos Digital" para Smart City
 * 
 * Implementa el flujo OAuth 2.0 Device Authorization Grant (RFC 8628)
 * con Atestación de Hardware (RSA) para registrarse de forma segura.
 * 
 * Transporte: HTTP directo al servidor Express (en un escenario real,
 * el CoAP UDP del dispositivo sería traducido por el proxy C al HTTP
 * que aquí enviamos directamente para mayor fiabilidad en la demo).
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocket } from 'ws';
import http from 'http';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const WS_URL   = 'ws://localhost:3000';
const SERVER_HOST = 'localhost';
const SERVER_PORT = 3000;
const DEVICE_ID   = 'smart-grid-frame-001';

let ws = null;
let devicePrivateKey = null;
let devicePublicKey  = null;
let deviceCert       = null;
let wsReconnectDelay = 1000;

// ==========================================================================
// COMUNICACIÓN CON LA INTERFAZ VÍA WEBSOCKET
// ==========================================================================

function connectWebSocket() {
  ws = new WebSocket(WS_URL);

  ws.on('open', () => {
    wsReconnectDelay = 1000; // reset backoff
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

  ws.on('error', () => {
    // El evento close se dispara después, allí hacemos reconexión
  });

  ws.on('close', () => {
    console.log(`[Device] WS desconectado. Reintentando en ${wsReconnectDelay}ms...`);
    setTimeout(connectWebSocket, wsReconnectDelay);
    wsReconnectDelay = Math.min(wsReconnectDelay * 2, 15000); // backoff exponencial
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

// ==========================================================================
// TRANSPORTE HTTP (SIMULA CoAP → HTTP PROXY)
// ==========================================================================

/**
 * Realiza una petición HTTP POST al servidor Express.
 * En el sistema real, el dispositivo enviaría CoAP UDP al proxy (puerto 5683)
 * y el proxy C traduciría el mensaje a este HTTP/JSON.
 */
function httpPost(pathname, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);

    const options = {
      hostname: SERVER_HOST,
      port:     SERVER_PORT,
      path:     pathname,
      method:   'POST',
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        // Cabecera que simula que la petición viene del proxy CoAP
        'X-CoAP-Proxy':  'true',
        'X-CoAP-Device': DEVICE_ID
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

// ==========================================================================
// FLUJO CRIPTOGRÁFICO DE ATESTACIÓN Y OAUTH 2.0 (RFC 8628)
// ==========================================================================

async function startDeviceRegistration() {
  sendUILog('start', '🔌 Encendiendo dispositivo e iniciando registro seguro...');
  updateUIState('REGISTERING', { message: 'Inicializando criptografía RSA...' });

  try {
    // ── PASO 1: Generar par de claves RSA en el "enclave seguro" del dispositivo ──
    sendUILog('crypt', '🔐 Generando par de claves RSA-2048 en el enclave seguro del hardware...');
    const keyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    devicePrivateKey = keyPair.privateKey;
    devicePublicKey  = keyPair.publicKey;
    const devicePubKeyPem = devicePublicKey.export({ type: 'pkcs1', format: 'pem' }).toString();
    sendUILog('crypt', '✅ Par de claves generado. Clave privada residente en el enclave (nunca sale del chip).');

    // ── PASO 2: Cargar clave del fabricante y crear el Certificado de Atestación ──
    const keysFile = path.join(__dirname, 'manufacturer_keys.json');
    if (!fs.existsSync(keysFile)) {
      throw new Error('manufacturer_keys.json no encontrado. Asegúrate de iniciar server.js primero.');
    }
    const keys = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
    const manufacturerPrivKey = crypto.createPrivateKey(keys.privateKey);

    sendUILog('crypt', '🏭 Firmando clave pública del dispositivo con la clave privada del Fabricante (CA)...');
    const certData      = `${DEVICE_ID}:${devicePubKeyPem}`;
    const certSignature = crypto.sign('sha256', Buffer.from(certData), manufacturerPrivKey);

    deviceCert = {
      device_id:              DEVICE_ID,
      device_pubkey:          devicePubKeyPem,
      manufacturer_signature: certSignature.toString('hex')
    };
    sendUILog('crypt', '📜 Certificado de Atestación de fábrica generado con éxito.', { device_id: DEVICE_ID });

    // ── PASO 3: Firmar la petición con la clave privada del dispositivo ──
    const timestamp      = Date.now().toString();
    const payloadToSign  = `${DEVICE_ID}:${timestamp}`;
    sendUILog('crypt', '✍️  Firmando petición con la clave privada del dispositivo...');
    const signature = crypto.sign('sha256', Buffer.from(payloadToSign), devicePrivateKey);

    // ── PASO 4: Enviar solicitud de autorización (RFC 8628 §3.1) ──
    sendUILog('req', `📤 Enviando CoAP POST → HTTP a /auth/device_authorize...`, {
      device_id: DEVICE_ID,
      timestamp
    });

    const authResponse = await httpPost('/auth/device_authorize', {
      client_id:               DEVICE_ID,
      timestamp,
      signature:               signature.toString('hex'),
      attestation_certificate: JSON.stringify(deviceCert)
    });

    if (authResponse.status !== 200) {
      throw new Error(`Servidor rechazó la atestación: ${JSON.stringify(authResponse.data)}`);
    }

    const authData = authResponse.data;
    sendUILog('res', `✅ Registro aceptado. Código de usuario: ${authData.user_code}`, authData);

    updateUIState('PENDING_USER', {
      user_code:        authData.user_code,
      verification_uri: authData.verification_uri_complete,
      expires_in:       authData.expires_in
    });

    // ── PASO 5: Iniciar polling de tokens (RFC 8628 §3.4) ──
    startTokenPolling(authData.device_code, authData.interval);

  } catch (err) {
    sendUILog('error', `❌ Error en el registro: ${err.message}`);
    updateUIState('ERROR', { error: err.message });
  }
}

// ── Polling de Tokens (RFC 8628 §3.4 & §3.5) ──
function startTokenPolling(device_code, interval) {
  let attempt = 0;

  const pollTimer = setInterval(async () => {
    attempt++;
    sendUILog('req', `🔄 Polling de tokens — Intento ${attempt} vía POST /auth/token...`);

    try {
      const response = await httpPost('/auth/token', {
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

      // ¡Éxito! Access Token obtenido
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

// ── Consumo del Servidor de Recursos con Token (RS) ──
async function downloadPhotos(access_token) {
  sendUILog('req', '📸 Solicitando catálogo de fotos al Servidor de Recursos con token Bearer...');

  try {
    const response = await httpPost('/api/photos', { access_token });

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

// ==========================================================================
// INICIO
// ==========================================================================
console.log('[Device] Iniciando cliente IoT - Portarretratos Digital...');
connectWebSocket();

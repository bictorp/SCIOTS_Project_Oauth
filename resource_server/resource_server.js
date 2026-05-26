import express from 'express';
import { fileURLToPath } from 'url';
import fs from 'fs';
import pathModule from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = pathModule.dirname(__filename);

const app = express();
app.use(express.json());

// Enable CORS for cross-origin requests from Dashboard (port 3000)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type,authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

const PORT = 3002;
const AUTH_SERVER_URL = 'http://localhost:3001';
const DASHBOARD_URL = 'http://localhost:3000';

// Helper to send logs to the Dashboard server so they appear in the UI console
async function logToDashboard(type, message, details = null) {
  try {
    const response = await fetch(`${DASHBOARD_URL}/api/logs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source: 'Resource Server',
        type,
        message,
        details
      })
    });
    if (!response.ok) {
      console.error('[RS] Failed to send log to Dashboard:', response.statusText);
    }
  } catch (err) {
    console.log(`[RS][${type.toUpperCase()}] ${message}`);
  }
}

// Token Introspection Middleware (Communicates with AS to validate)
async function authenticateToken(req, res, next) {
  let token = null;
  const authHeader = req.headers['authorization'];
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (req.body && req.body.access_token) {
    token = req.body.access_token;
  }

  if (!token) {
    await logToDashboard('ERROR', `Acceso denegado: Petición sin token de acceso.`);
    return res.status(401).json({ error: 'access_denied', message: 'Missing token' });
  }

  try {
    // Introspect the token via the AS REST API
    const response = await fetch(`${AUTH_SERVER_URL}/auth/validate_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ access_token: token })
    });

    if (!response.ok) {
      throw new Error(`AS returned status ${response.status}`);
    }

    const tokenInfo = await response.json();

    if (!tokenInfo.active) {
      await logToDashboard('ERROR', `Acceso denegado: Token inválido o revocado.`);
      return res.status(403).json({ error: 'invalid_token', message: 'Invalid token' });
    }

    // Attach client_id and scopes to request
    req.client_id = tokenInfo.client_id;
    req.scope = tokenInfo.scope;
    
    next();

  } catch (err) {
    await logToDashboard('ERROR', `Error al validar token con AS: ${err.message}`);
    return res.status(500).json({ error: 'server_error', message: 'Auth server communication failed' });
  }
}

// Servir la carpeta de imágenes protegidas
const imagesDir = pathModule.join(__dirname, 'public', 'images');
fs.mkdirSync(imagesDir, { recursive: true });

app.get('/health', (req, res) => {
  res.json({ status: 'online', service: 'resource-server' });
});

/**
 * 1. GET/POST /api/photos: Devuelve catálogo de fotos (protegido por token)
 */
app.all('/api/photos', authenticateToken, async (req, res) => {
  await logToDashboard('SUCCESS', `Petición autorizada para ${req.client_id}. Devolviendo catálogo de imágenes.`);

  const photoList = [
    { id: 1, name: 'Smart City Landscape', url: `http://localhost:${PORT}/api/photos/1` },
    { id: 2, name: 'IoT Node Hardware', url: `http://localhost:${PORT}/api/photos/2` },
    { id: 3, name: 'Control Room Grid', url: `http://localhost:${PORT}/api/photos/3` },
    { id: 4, name: 'Digital Grid Networks', url: `http://localhost:${PORT}/api/photos/4` }
  ];

  res.json({ photos: photoList });
});

/**
 * 2. GET/POST /api/photos/:id: Devuelve archivo binario físico de la foto (protegido por token)
 */
app.all('/api/photos/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const imagePath = pathModule.join(imagesDir, `foto${id}.png`);

  if (!fs.existsSync(imagePath)) {
    await logToDashboard('ERROR', `Imagen no encontrada en el disco: foto${id}.png`);
    return res.status(404).json({ error: 'photo_not_found' });
  }

  await logToDashboard('SUCCESS', `Enviando imagen física foto${id}.png para ${req.client_id}`);
  res.sendFile(imagePath);
});

app.listen(PORT, () => {
  console.log(`📸 [Resource Server] Running on http://localhost:${PORT}`);
});

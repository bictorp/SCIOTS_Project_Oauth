import express from 'express';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocketServer, WebSocket } from 'ws';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Serve static files from dashboard_device/public
app.use(express.static(path.join(__dirname, 'public')));

const PORT = 3000;

// WS client pools
const uiClients = new Set();
let deviceSocket = null;

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'online', service: 'dashboard-server' });
});

/**
 * API Endpoint: Receive logs from AS and RS and broadcast them to all UI clients
 */
app.post('/api/logs', (req, res) => {
  const { source, type, message, details } = req.body;
  broadcastToUI('log', { source, type, message, details });
  res.json({ status: 'logged' });
});

/**
 * API Endpoint: AS notifies that the user approved the user_code
 */
app.post('/api/device/authorized', (req, res) => {
  const { device_code } = req.body;
  
  // Send authorization event to UI and device
  const payload = JSON.stringify({ event: 'device_authorized', data: { device_code } });
  
  for (const client of uiClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }

  if (deviceSocket && deviceSocket.readyState === WebSocket.OPEN) {
    deviceSocket.send(payload);
  }

  res.json({ status: 'notified' });
});

// Broadcast helper for UI
function broadcastToUI(event, data) {
  const payload = JSON.stringify({ event, data });
  for (const client of uiClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
}

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  // Determine if it is a UI client (browser) or the Device client based on headers or query parameters
  const isDevice = req.headers['user-agent'] === undefined || req.url.includes('role=device');

  if (isDevice) {
    deviceSocket = ws;
    console.log('📡 Device Client connected via WebSocket.');
    
    ws.on('message', (message) => {
      try {
        const parsed = JSON.parse(message);
        
        if (parsed.event === 'device_log') {
          broadcastToUI('log', parsed.data);
        }
        if (parsed.event === 'device_state') {
          broadcastToUI('device_state', parsed.data);
        }
      } catch (e) {
        // Ignore malformed messages
      }
    });

    ws.on('close', () => {
      deviceSocket = null;
      console.log('❌ Device Client disconnected.');
    });
  } else {
    uiClients.add(ws);
    console.log('💻 Dashboard UI Client connected via WebSocket.');

    ws.on('message', (message) => {
      try {
        const parsed = JSON.parse(message);
        // User clicked "Encender y Registrar" -> forward to the device
        if (parsed.event === 'start_registration') {
          if (deviceSocket && deviceSocket.readyState === WebSocket.OPEN) {
            deviceSocket.send(JSON.stringify({ event: 'start_registration' }));
          } else {
            broadcastToUI('log', {
              source: 'Sistema',
              type: 'ERROR',
              message: 'El dispositivo físico no está encendido o conectado. Inicia device.js primero.'
            });
          }
        }
      } catch (e) {
        // Ignore
      }
    });

    ws.on('close', () => {
      uiClients.delete(ws);
      console.log('💻 Dashboard UI Client disconnected.');
    });
  }
});

server.listen(PORT, () => {
  console.log(`🖼️ [Dashboard & Broker] Running on http://localhost:${PORT}`);
});

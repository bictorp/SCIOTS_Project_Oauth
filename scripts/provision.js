import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Target Directories
const ROOT_DIR = path.join(__dirname, '..');
const AUTH_SERVER_DIR = path.join(ROOT_DIR, 'auth_server');
const DASHBOARD_DEVICE_DIR = path.join(ROOT_DIR, 'dashboard_device');

// Ensure directories exist
fs.mkdirSync(AUTH_SERVER_DIR, { recursive: true });
fs.mkdirSync(DASHBOARD_DEVICE_DIR, { recursive: true });

console.log('🏭 Starting Factory Provisioning Process for SCIOTS Device...');

// 1. Generate/Load Manufacturer CA Keys
console.log('🔑 Generating Manufacturer CA Keys...');
const manufacturerKeyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const manufacturerPrivKey = manufacturerKeyPair.privateKey;
const manufacturerPubKey = manufacturerKeyPair.publicKey;

const manufacturerPubKeyPem = manufacturerPubKey.export({ type: 'pkcs1', format: 'pem' }).toString();
const manufacturerPrivKeyPem = manufacturerPrivKey.export({ type: 'pkcs1', format: 'pem' }).toString();

// Write public key to auth_server (so the auth server can verify attestation certs)
fs.writeFileSync(path.join(AUTH_SERVER_DIR, 'manufacturer_pubkey.pem'), manufacturerPubKeyPem);
console.log('✅ Exported Manufacturer Public Key to auth_server/manufacturer_pubkey.pem');

// 2. Generate Device Keypair (representing the unique hardware key of the smart photo frame)
const DEVICE_ID = 'smart-grid-frame-001';
console.log(`🔒 Generating Hardware Keypair for Device: ${DEVICE_ID}...`);
const deviceKeyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const devicePrivKey = deviceKeyPair.privateKey;
const devicePubKey = deviceKeyPair.publicKey;

const devicePubKeyPem = devicePubKey.export({ type: 'pkcs1', format: 'pem' }).toString();
const devicePrivKeyPem = devicePrivKey.export({ type: 'pkcs1', format: 'pem' }).toString();

// 3. Create Factory Attestation Certificate signed by the Manufacturer's Private Key
console.log('📜 Signing Device Public Key with Manufacturer CA to create Attestation Certificate...');
const certData = `${DEVICE_ID}:${devicePubKeyPem}`;
const certSignature = crypto.sign('sha256', Buffer.from(certData), manufacturerPrivKey);

const attestationCertificate = {
  device_id: DEVICE_ID,
  device_pubkey: devicePubKeyPem,
  manufacturer_signature: certSignature.toString('hex')
};

// 4. Save device credentials (private key + cert) to dashboard_device
const deviceCredentials = {
  device_id: DEVICE_ID,
  device_private_key: devicePrivKeyPem,
  attestation_certificate: attestationCertificate
};

fs.writeFileSync(
  path.join(DASHBOARD_DEVICE_DIR, 'device_credentials.json'),
  JSON.stringify(deviceCredentials, null, 2)
);
console.log('✅ Exported Device Credentials to dashboard_device/device_credentials.json');
console.log('🎉 Provisioning complete! Device now holds its private key and manufacturer-signed certificate.');

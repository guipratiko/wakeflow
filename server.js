/**
 * Backend WakeFlow – OAuth (Account Linking), Skill Custom, Smart Home, Dashboard, API dispositivo
 */

const express = require('express');
const fs = require('fs');
const dgram = require('dgram');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');

const CLIENT_ID = process.env.OAUTH_CLIENT_ID || 'amzn1.application-oa2-client.540128c73c284db38835ac80be42ac9d';
const CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || '';
const USERS = (process.env.OAUTH_USERS || 'admin:admin')
  .split(',')
  .map(s => {
    const [u, p] = s.trim().split(':');
    return u && p ? { username: u, password: p } : null;
  })
  .filter(Boolean);

const LOG_REQUESTS = process.env.LOG_REQUESTS !== 'false';
const DATA_DIR = path.join(__dirname, 'data');
const TOKENS_FILE = path.join(DATA_DIR, 'accessTokens.json');
const DEVICES_FILE = path.join(DATA_DIR, 'devices.json');
const LICENSES_FILE = path.join(DATA_DIR, 'licenses.json');

const authCodes = new Map();
const authSessions = new Map();
const CODE_TTL_MS = 10 * 60 * 1000;
const TOKEN_TTL_SEC = 3600;
const SESSION_TTL_MS = 10 * 60 * 1000;
const DASHBOARD_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

function loadJSON(filePath, def = {}) {
  try {
    if (fs.existsSync(filePath)) return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) { console.warn('load', filePath, e.message); }
  return def;
}

function saveJSON(filePath, obj) {
  try {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(obj), 'utf8');
  } catch (e) { console.warn('save', filePath, e.message); }
}

const accessTokensData = loadJSON(TOKENS_FILE, {});
const accessTokens = new Map();
const now = Date.now();
for (const [token, obj] of Object.entries(accessTokensData)) {
  if (obj && obj.expiresAt > now) accessTokens.set(token, { userId: obj.userId, expiresAt: obj.expiresAt });
}

function saveAccessTokens() {
  const obj = {};
  for (const [t, d] of accessTokens.entries()) obj[t] = d;
  saveJSON(TOKENS_FILE, obj);
}

function loadDevices() {
  const data = loadJSON(DEVICES_FILE, {});
  const map = new Map();
  for (const [k, v] of Object.entries(data)) if (v) map.set(k, v);
  return map;
}

function saveDevices() {
  const obj = {};
  for (const [k, v] of devices.entries()) obj[k] = v;
  saveJSON(DEVICES_FILE, obj);
}

function loadLicenses() {
  const data = loadJSON(LICENSES_FILE, {});
  const map = new Map();
  for (const [k, v] of Object.entries(data)) if (v) map.set(k, v);
  return map;
}

function saveLicenses() {
  const obj = {};
  for (const [k, v] of licenses.entries()) obj[k] = v;
  saveJSON(LICENSES_FILE, obj);
}

const devices = loadDevices();
const licenses = loadLicenses();
const dashboardSessions = new Map();

function normalizeMac(mac) {
  if (!mac || typeof mac !== 'string') return '';
  return mac.replace(/[-:]/g, '').toLowerCase().slice(0, 12);
}

function macForAlexa(macNorm) {
  if (!macNorm || macNorm.length !== 12) return '';
  return macNorm.match(/.{2}/g).map(s => s.toUpperCase()).join('-');
}

function findUser(username, password) {
  return USERS.find(u => u.username === username && u.password === password) || null;
}

function userIdFromAccessToken(token) {
  const d = accessTokens.get(token);
  if (!d || d.expiresAt < Date.now()) return null;
  return d.userId;
}

function getCookie(req, name) {
  const m = (req.headers.cookie || '').match(new RegExp(name + '=([^;]+)'));
  return m ? m[1].trim() : null;
}

function sendWolMagicPacket(macNorm, host, port, cb) {
  if (!macNorm || macNorm.length !== 12) return cb(new Error('MAC inválido'));
  const macBytes = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) macBytes[i] = parseInt(macNorm.slice(i * 2, i * 2 + 2), 16);
  const packet = Buffer.alloc(102);
  packet.fill(0xff, 0, 6);
  for (let i = 0; i < 16; i++) macBytes.copy(packet, 6 + i * 6);
  const client = dgram.createSocket('udp4');
  client.send(packet, 0, packet.length, port, host, (err) => { client.close(); cb(err); });
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  if (LOG_REQUESTS && (req.method === 'POST' || req.path === '/oauth/authorize')) {
    const body = req.body && typeof req.body === 'object' ? { ...req.body } : undefined;
    if (body && body.password) body.password = '[REDACTED]';
    if (body && body.client_secret) body.client_secret = '[REDACTED]';
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`, body ? { body } : '');
  }
  next();
});

// ---------- GET /oauth/authorize ----------
app.get('/oauth/authorize', (req, res) => {
  const client_id = req.query.client_id || req.body?.client_id;
  const redirect_uri = req.query.redirect_uri || req.body?.redirect_uri;
  const response_type = req.query.response_type || req.body?.response_type;
  const state = req.query.state || req.body?.state;
  const scope = req.query.scope || req.body?.scope || '';

  if (!client_id || !redirect_uri || !state) {
    return res.status(400).send('client_id, redirect_uri e state são obrigatórios');
  }

  const sid = uuidv4().replace(/-/g, '');
  authSessions.set(sid, {
    client_id,
    redirect_uri,
    response_type,
    state,
    scope,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  res.setHeader('Set-Cookie', `oauth_sid=${sid}; Path=/; Max-Age=600; HttpOnly; SameSite=Lax`);
  res.redirect('/login.html');
});

// ---------- POST /oauth/authorize (login) ----------
app.post('/oauth/authorize', (req, res) => {
  const sid = getCookie(req, 'oauth_sid');
  const session = sid ? authSessions.get(sid) : null;
  if (!session || session.expiresAt < Date.now()) {
    authSessions.delete(sid);
    return res.status(400).send('Sessão expirada. Volte à Alexa e tente vincular de novo.');
  }

  const { username, password } = req.body || {};
  const user = findUser(String(username || '').trim(), password != null ? String(password) : '');
  if (!user) {
    return res.redirect('/login.html?error=invalid');
  }

  const code = uuidv4().replace(/-/g, '');
  authCodes.set(code, { userId: user.username, expiresAt: Date.now() + CODE_TTL_MS });
  authSessions.delete(sid);
  res.setHeader('Set-Cookie', 'oauth_sid=; Path=/; Max-Age=0');
  const redirect = `${session.redirect_uri}?code=${code}&state=${encodeURIComponent(session.state)}`;
  res.redirect(redirect);
});

// ---------- POST /oauth/token ----------
app.post('/oauth/token', (req, res) => {
  const auth = req.headers.authorization || '';
  const basic = auth.startsWith('Basic ') ? Buffer.from(auth.slice(6), 'base64').toString() : '';
  const [clientId, clientSecret] = basic ? basic.split(':') : [req.body?.client_id, req.body?.client_secret];

  if (clientId !== CLIENT_ID || (CLIENT_SECRET && clientSecret !== CLIENT_SECRET)) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  const { grant_type, code } = req.body || {};
  if (grant_type !== 'authorization_code' || !code) {
    return res.status(400).json({ error: 'invalid_request' });
  }

  const data = authCodes.get(code);
  if (!data || data.expiresAt < Date.now()) {
    authCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant' });
  }
  authCodes.delete(code);

  const token = uuidv4().replace(/-/g, '');
  accessTokens.set(token, { userId: data.userId, expiresAt: Date.now() + TOKEN_TTL_SEC * 1000 });
  saveAccessTokens();

  res.json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: TOKEN_TTL_SEC,
  });
});

// ---------- Skill Custom GET ----------
app.get(['/skill', '/skill/'], (req, res) => {
  res.json({ skill: 'WakeFlow', endpoint: 'POST para este URL' });
});

// ---------- Skill Custom POST ----------
function buildAlexaResponse(outputText, endSession = true) {
  return {
    version: '1.0',
    response: {
      outputSpeech: { type: 'PlainText', text: outputText },
      shouldEndSession: endSession,
    },
  };
}

app.post(['/skill', '/skill/'], (req, res) => {
  const body = req.body || {};
  const requestType = body.request?.type;
  const intentName = body.request?.intent?.name;
  let outputText = 'Não entendi.';

  if (requestType === 'LaunchRequest') {
    outputText = 'Diga ligar o computador ou desligar o computador.';
  } else if (requestType === 'IntentRequest') {
    if (intentName === 'LigarPC') {
      const token = body.session?.user?.accessToken;
      const userId = token ? userIdFromAccessToken(token) : null;
      if (!userId) {
        outputText = 'Vincule sua conta na Alexa para usar este comando.';
      } else {
        let sent = false;
        for (const [, d] of devices.entries()) {
          if (d.userId === userId && d.mac && d.wolTargetHost) {
            const port = d.wolTargetPort || 9;
            sendWolMagicPacket(d.mac, d.wolTargetHost.trim(), port, () => {});
            sent = true;
            outputText = 'Ok, ligando o computador.';
            break;
          }
        }
        if (!sent) outputText = 'Configure o IP ou hostname para ligar o PC no dashboard do WakeFlow.';
      }
    } else if (intentName === 'DesligarPC') {
      const token = body.session?.user?.accessToken;
      const userId = token ? userIdFromAccessToken(token) : null;
      if (userId) {
        for (const [, d] of devices.entries()) {
          if (d.userId === userId && d.deviceToken) {
            d.pendingCommand = 'shutdown';
            saveDevices();
            break;
          }
        }
      }
      outputText = 'Ok, desligando o computador.';
    } else if (intentName === 'AMAZON.CancelIntent' || intentName === 'AMAZON.StopIntent') {
      outputText = 'Até logo.';
    } else if (intentName === 'AMAZON.HelpIntent') {
      outputText = 'Diga: ligar o computador, ou desligar o computador.';
    }
  }

  res.type('application/json').status(200).json(buildAlexaResponse(outputText));
});

// ---------- Smart Home ----------
const ALEXA_EVENT_GATEWAY_URL = process.env.ALEXA_EVENT_GATEWAY_URL || 'https://api.amazonalexa.com/v3/events';

app.get(['/smarthome', '/smarthome/'], (req, res) => {
  res.json({ smarthome: true, message: 'WakeFlow Smart Home' });
});

async function sendToEventGateway(accessToken, payload) {
  const res = await fetch(ALEXA_EVENT_GATEWAY_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (LOG_REQUESTS) console.log('[SMARTHOME] Event Gateway:', res.status);
  return res;
}

app.post('/smarthome', (req, res) => {
  let body = req.body;
  if (typeof body === 'string') try { body = JSON.parse(body); } catch { body = {}; }
  body = body || {};

  let directive = body.directive || body.Directive;
  if (!directive && body.request) {
    const req_ = body.request;
    directive = req_.directive || req_.Directive;
    if (!directive && req_.header && (req_.header.namespace || req_.header.Namespace)) {
      directive = {
        header: {
          namespace: req_.header.namespace || req_.header.Namespace,
          name: req_.header.name || req_.header.Name,
          messageId: req_.header.messageId || uuidv4(),
          correlationToken: req_.header.correlationToken || '',
          payloadVersion: req_.header.payloadVersion || '3',
        },
        endpoint: req_.endpoint || {},
        payload: req_.payload || {},
      };
    }
    if (!directive && req_.namespace && req_.name) {
      directive = {
        header: {
          namespace: req_.namespace,
          name: req_.name,
          messageId: req_.messageId || uuidv4(),
          correlationToken: req_.correlationToken || '',
          payloadVersion: req_.payloadVersion || '3',
        },
        endpoint: req_.endpoint || {},
        payload: req_.payload || {},
      };
    }
  }
  if (!directive && body.header && body.endpoint) {
    directive = { header: body.header, endpoint: body.endpoint, payload: body.payload || {} };
  }

  if (!directive || !directive.header) {
    const req_ = body.request;
    if (req_ && (req_.type === 'IntentRequest' || req_.type === 'SessionEndedRequest')) {
      return res.status(200).json({
        version: '1.0',
        response: {
          outputSpeech: { type: 'PlainText', text: 'Este endpoint é para a skill Smart Home. Crie uma skill do tipo Smart Home no Developer Console.' },
          shouldEndSession: true,
        },
      });
    }
    return res.status(400).json({ error: 'Invalid directive' });
  }

  const ns = directive.header.namespace;
  const name = directive.header.name;
  const correlationToken = directive.header.correlationToken || '';
  const endpoint = directive.endpoint || {};
  const payload = directive.payload || {};
  const scope = endpoint.scope || payload.scope || {};
  const token = scope.token || '';
  const endpointId = endpoint.endpointId || '';
  const userId = token ? userIdFromAccessToken(token) : null;

  // Discover
  if (ns === 'Alexa.Discovery' && name === 'Discover') {
    const endpoints = [];
    for (const [devId, d] of devices.entries()) {
      if (d.userId !== userId || !d.mac) continue;
      const macAlexa = macForAlexa(d.mac);
      if (!macAlexa) continue;
      endpoints.push({
        endpointId: devId,
        manufacturerName: 'WakeFlow',
        description: 'Computador Wake-on-LAN',
        friendlyName: d.name || 'Computador',
        displayCategories: ['COMPUTER'],
        cookie: {},
        capabilities: [
          { type: 'AlexaInterface', interface: 'Alexa.WakeOnLANController', version: '3', properties: {}, configuration: { MACAddresses: [macAlexa] } },
          { type: 'AlexaInterface', interface: 'Alexa.PowerController', version: '3', properties: { supported: [{ name: 'powerState' }], proactivelyReported: true, retrievable: true } },
          { type: 'AlexaInterface', interface: 'Alexa.EndpointHealth', version: '3', properties: { supported: [{ name: 'connectivity' }], proactivelyReported: true, retrievable: true } },
          { type: 'AlexaInterface', interface: 'Alexa', version: '3' },
        ],
      });
    }
    return res.status(200).json({
      event: {
        header: { namespace: 'Alexa.Discovery', name: 'Discover.Response', payloadVersion: '3', messageId: uuidv4() },
        payload: { endpoints },
      },
    });
  }

  // TurnOn (WoL pelo Echo)
  if (ns === 'Alexa.PowerController' && name === 'TurnOn') {
    if (!userId || !endpointId || !devices.has(endpointId)) {
      return res.status(200).json({
        event: {
          header: { namespace: 'Alexa', name: 'ErrorResponse', messageId: uuidv4(), correlationToken, payloadVersion: '3' },
          endpoint: directive.endpoint,
          payload: { type: 'ENDPOINT_UNREACHABLE', message: 'Dispositivo não encontrado' },
        },
      });
    }
    res.status(200).json({
      event: {
        header: { namespace: 'Alexa', name: 'DeferredResponse', messageId: uuidv4(), correlationToken, payloadVersion: '3' },
        payload: { estimatedDeferralInSeconds: 5 },
      },
    });
    const now = new Date().toISOString();
    const wakeUp = {
      event: {
        header: { namespace: 'Alexa.WakeOnLANController', name: 'WakeUp', messageId: uuidv4(), correlationToken, payloadVersion: '3' },
        endpoint: { scope: { type: 'BearerToken', token }, endpointId },
        payload: {},
      },
      context: { properties: [{ namespace: 'Alexa.PowerController', name: 'powerState', value: 'ON', timeOfSample: now, uncertaintyInMilliseconds: 500 }] },
    };
    const responseEvent = {
      event: {
        header: { namespace: 'Alexa', name: 'Response', messageId: uuidv4(), correlationToken, payloadVersion: '3' },
        endpoint: { scope: { type: 'BearerToken', token }, endpointId },
        payload: {},
      },
      context: { properties: [{ namespace: 'Alexa.PowerController', name: 'powerState', value: 'ON', timeOfSample: now, uncertaintyInMilliseconds: 500 }] },
    };
    (async () => {
      try {
        const r = await sendToEventGateway(token, wakeUp);
        if (r.status === 202) await sendToEventGateway(token, responseEvent);
      } catch (e) { if (LOG_REQUESTS) console.log('[SMARTHOME] Gateway error', e.message); }
    })();
    return;
  }

  // TurnOff
  if (ns === 'Alexa.PowerController' && name === 'TurnOff') {
    const device = devices.get(endpointId);
    if (device && device.userId === userId && device.deviceToken) {
      device.pendingCommand = 'shutdown';
      saveDevices();
    }
    const now = new Date().toISOString();
    return res.status(200).json({
      event: {
        header: { namespace: 'Alexa', name: 'Response', messageId: uuidv4(), correlationToken, payloadVersion: '3' },
        endpoint: { scope: { type: 'BearerToken', token }, endpointId },
        payload: {},
      },
      context: { properties: [{ namespace: 'Alexa.PowerController', name: 'powerState', value: 'OFF', timeOfSample: now, uncertaintyInMilliseconds: 0 }] },
    });
  }

  // ReportState
  if (ns === 'Alexa' && name === 'ReportState') {
    const now = new Date().toISOString();
    return res.status(200).json({
      event: {
        header: { namespace: 'Alexa', name: 'StateReport', messageId: uuidv4(), correlationToken, payloadVersion: '3' },
        endpoint: { scope: { type: 'BearerToken', token }, endpointId },
        payload: {},
      },
      context: {
        properties: [
          { namespace: 'Alexa.PowerController', name: 'powerState', value: 'OFF', timeOfSample: now, uncertaintyInMilliseconds: 0 },
          { namespace: 'Alexa.EndpointHealth', name: 'connectivity', value: { value: 'OK' }, timeOfSample: now, uncertaintyInMilliseconds: 0 },
        ],
      },
    });
  }

  res.status(200).json({
    event: {
      header: { namespace: 'Alexa', name: 'ErrorResponse', messageId: uuidv4(), correlationToken, payloadVersion: '3' },
      endpoint: directive.endpoint ? { endpointId: directive.endpoint.endpointId } : {},
      payload: { type: 'INVALID_DIRECTIVE', message: 'Not supported' },
    },
  });
});

// ---------- Dashboard ----------
function getDashboardUser(req) {
  const sid = getCookie(req, 'dashboard_sid');
  if (!sid) return null;
  const s = dashboardSessions.get(sid);
  if (!s || s.expiresAt < Date.now()) {
    dashboardSessions.delete(sid);
    return null;
  }
  return s.userId;
}

app.get('/dashboard', (req, res) => {
  if (!getDashboardUser(req)) return res.redirect('/dashboard/login');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/dashboard/login', (req, res) => {
  if (getDashboardUser(req)) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'dashboard-login.html'));
});

app.post('/dashboard/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = findUser(String(username || '').trim(), password != null ? String(password) : '');
  if (!user) return res.redirect('/dashboard/login?error=invalid');
  const sid = uuidv4().replace(/-/g, '');
  dashboardSessions.set(sid, { userId: user.username, expiresAt: Date.now() + DASHBOARD_SESSION_TTL_MS });
  const secure = BASE_URL.startsWith('https');
  res.setHeader('Set-Cookie', `dashboard_sid=${sid}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`);
  res.redirect('/dashboard');
});

app.post('/dashboard/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'dashboard_sid=; Path=/; Max-Age=0');
  res.redirect('/dashboard/login');
});

app.get('/dashboard/api/devices', (req, res) => {
  const userId = getDashboardUser(req);
  if (!userId) return res.status(401).json({ error: 'Não autenticado' });
  const list = [];
  for (const [deviceId, d] of devices.entries()) {
    if (d.userId === userId) {
      list.push({
        deviceId,
        mac: d.mac,
        name: d.name || 'PC',
        lastSeen: d.lastSeen,
        hasClient: !!d.deviceToken,
        licenseKey: d.licenseKey || null,
        wolTargetHost: d.wolTargetHost || null,
        wolTargetPort: d.wolTargetPort ?? 9,
      });
    }
  }
  res.json({ devices: list });
});

app.post('/dashboard/api/devices', (req, res) => {
  const userId = getDashboardUser(req);
  if (!userId) return res.status(401).json({ error: 'Não autenticado' });
  const { mac, name, wolTargetHost, wolTargetPort } = req.body || {};
  const macNorm = normalizeMac(mac);
  if (!macNorm || macNorm.length < 12) return res.status(400).json({ error: 'MAC inválido' });
  const deviceId = uuidv4().replace(/-/g, '');
  const deviceToken = uuidv4().replace(/-/g, '');
  const licenseKey = 'WF-' + uuidv4().replace(/-/g, '').toUpperCase().slice(0, 16);
  const wolPort = wolTargetPort != null ? parseInt(wolTargetPort, 10) : 9;
  devices.set(deviceId, {
    userId,
    mac: macNorm,
    name: (name && String(name).trim()) || 'PC',
    deviceToken,
    licenseKey,
    wolTargetHost: (wolTargetHost && String(wolTargetHost).trim()) || null,
    wolTargetPort: Number.isFinite(wolPort) ? wolPort : 9,
    pendingCommand: null,
    lastSeen: null,
    createdAt: Date.now(),
  });
  licenses.set(licenseKey, { userId, deviceId, createdAt: Date.now() });
  saveDevices();
  saveLicenses();
  res.status(201).json({ deviceId, licenseKey, message: 'Use esta licença no software Windows.' });
});

app.patch('/dashboard/api/devices/:deviceId', (req, res) => {
  const userId = getDashboardUser(req);
  if (!userId) return res.status(401).json({ error: 'Não autenticado' });
  const device = devices.get(req.params.deviceId);
  if (!device || device.userId !== userId) return res.status(404).json({ error: 'Dispositivo não encontrado' });
  const { wolTargetHost, wolTargetPort } = req.body || {};
  if (wolTargetHost !== undefined) device.wolTargetHost = wolTargetHost ? String(wolTargetHost).trim() : null;
  if (wolTargetPort !== undefined) {
    const p = parseInt(wolTargetPort, 10);
    device.wolTargetPort = Number.isFinite(p) ? p : 9;
  }
  saveDevices();
  res.json({ ok: true, deviceId: req.params.deviceId });
});

// ---------- API dispositivo (cliente Windows) ----------
app.post('/api/device/register', (req, res) => {
  const { licenseKey, mac } = req.body || {};
  const macNorm = normalizeMac(mac);
  if (!licenseKey || !macNorm) return res.status(400).json({ error: 'licenseKey e mac são obrigatórios' });
  const lic = licenses.get(String(licenseKey).trim());
  if (!lic) return res.status(404).json({ error: 'Licença inválida' });
  const device = devices.get(lic.deviceId);
  if (!device) return res.status(404).json({ error: 'Dispositivo não encontrado' });
  if (device.mac !== macNorm) return res.status(400).json({ error: 'MAC não confere' });
  device.deviceToken = device.deviceToken || uuidv4().replace(/-/g, '');
  device.lastSeen = new Date().toISOString();
  saveDevices();
  res.json({ deviceId: lic.deviceId, deviceToken: device.deviceToken });
});

app.get('/api/device/poll', (req, res) => {
  const deviceId = req.query.deviceId || req.headers['x-device-id'];
  const deviceToken = req.query.deviceToken || req.headers['x-device-token'];
  if (!deviceId || !deviceToken) return res.status(401).json({ error: 'deviceId e deviceToken obrigatórios' });
  const device = devices.get(deviceId);
  if (!device || device.deviceToken !== deviceToken) return res.status(401).json({ error: 'Não autorizado' });
  device.lastSeen = new Date().toISOString();
  const command = device.pendingCommand || null;
  if (command) device.pendingCommand = null;
  saveDevices();
  res.json({ command });
});

app.get('/health', (req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`WakeFlow rodando em ${BASE_URL}`);
  console.log(`  OAuth: ${BASE_URL}/oauth/authorize | ${BASE_URL}/oauth/token`);
  console.log(`  Skill: ${BASE_URL}/skill | Smart Home: ${BASE_URL}/smarthome`);
  console.log(`  Dashboard: ${BASE_URL}/dashboard`);
});

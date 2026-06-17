const express = require('express');
const cors = require('cors');
const path = require('path');
const { randomUUID } = require('crypto');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let users = [];
let keys = [];

// ── AUTH ──────────────────────────────────────────────

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Kullanici adi ve sifre zorunlu' });
  if (users.find(u => u.username === username))
    return res.status(400).json({ error: 'Bu kullanici zaten var' });
  const newUser = { id: randomUUID(), username, password, isAdmin: users.length === 0 };
  users.push(newUser);
  res.json({ message: 'Kayit basarili', user: { id: newUser.id, username: newUser.username, isAdmin: newUser.isAdmin } });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Gecersiz kimlik bilgileri' });
  res.json({ message: 'Giris basarili', user: { id: user.id, username: user.username, isAdmin: user.isAdmin } });
});

// ── KEYS ──────────────────────────────────────────────

const generateKey = () =>
  'VNHX-XXXX-XXXX-XXXX'.replace(/[X]/g, () => (Math.random() * 36 | 0).toString(36).toUpperCase());

app.post('/api/keys', (req, res) => {
  const { durationHours, maxDevices } = req.body;
  const max = parseInt(maxDevices) || 1;
  const newKey = {
    key: generateKey(),
    createdAt: new Date().toISOString(),
    expiresAt: durationHours === 'infinite'
      ? null
      : new Date(Date.now() + parseFloat(durationHours) * 60 * 60 * 1000).toISOString(),
    isInfinite: durationHours === 'infinite',
    isActive: true,
    maxDevices: max,
    hwids: []   // birden fazla cihaz tutuyoruz
  };
  keys.push(newKey);
  res.json({ message: 'Key olusturuldu', key: newKey });
});

app.get('/api/keys', (req, res) => res.json(keys));

app.delete('/api/keys/:key', (req, res) => {
  const before = keys.length;
  keys = keys.filter(k => k.key !== req.params.key);
  if (keys.length === before) return res.status(404).json({ error: 'Key bulunamadi' });
  res.json({ message: 'Key silindi' });
});

app.patch('/api/keys/:key/toggle', (req, res) => {
  const keyRecord = keys.find(k => k.key === req.params.key);
  if (!keyRecord) return res.status(404).json({ error: 'Key bulunamadi' });
  keyRecord.isActive = !keyRecord.isActive;
  res.json({ message: 'Key durumu guncellendi', key: keyRecord });
});

app.patch('/api/keys/:key/resethwid', (req, res) => {
  const keyRecord = keys.find(k => k.key === req.params.key);
  if (!keyRecord) return res.status(404).json({ error: 'Key bulunamadi' });
  keyRecord.hwids = [];
  res.json({ message: 'HWID sifirlandi', key: keyRecord });
});

// ── VERIFY ────────────────────────────────────────────

app.post('/api/verify', (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.status(400).json({ error: 'Key ve HWID gerekli' });

  const keyRecord = keys.find(k => k.key === key);
  if (!keyRecord) return res.status(404).json({ error: 'Gecersiz Key' });
  if (!keyRecord.isActive) return res.status(403).json({ error: 'Bu Key devre disi' });
  if (!keyRecord.isInfinite && new Date() > new Date(keyRecord.expiresAt))
    return res.status(403).json({ error: 'Key suresi dolmus' });

  // hwids dizisi yoksa eski formattan migrate et
  if (!keyRecord.hwids) {
    keyRecord.hwids = keyRecord.hwid ? [keyRecord.hwid] : [];
    delete keyRecord.hwid;
  }

  if (keyRecord.hwids.includes(hwid)) {
    // zaten kayitli cihaz
    return res.json({ message: 'Dogrulama Basarili', status: 'OK', expiresAt: keyRecord.expiresAt });
  }

  if (keyRecord.hwids.length >= keyRecord.maxDevices) {
    return res.status(403).json({
      error: `Bu Key maksimum cihaz limitine ulasti (${keyRecord.maxDevices} cihaz)`
    });
  }

  keyRecord.hwids.push(hwid);
  res.json({ message: 'Dogrulama Basarili', status: 'OK', expiresAt: keyRecord.expiresAt });
});

module.exports = app;

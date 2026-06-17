const express = require('express');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Veriler RAM'de tutuluyor (Render, Railway gibi platformlarda disk sifirlanir)
let users = [];
let keys = [];

// ── AUTH ──────────────────────────────────────────────

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Kullanici adi ve sifre zorunlu' });

  if (users.find(u => u.username === username))
    return res.status(400).json({ error: 'Bu kullanici zaten var' });

  const newUser = {
    id: uuidv4(),
    username,
    password,
    isAdmin: users.length === 0
  };
  users.push(newUser);
  res.json({ message: 'Kayit basarili', user: { id: newUser.id, username: newUser.username, isAdmin: newUser.isAdmin } });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user)
    return res.status(401).json({ error: 'Gecersiz kimlik bilgileri' });

  res.json({ message: 'Giris basarili', user: { id: user.id, username: user.username, isAdmin: user.isAdmin } });
});

// ── KEYS ──────────────────────────────────────────────

const generateKey = () =>
  'VNHX-XXXX-XXXX-XXXX'.replace(/[X]/g, () =>
    (Math.random() * 36 | 0).toString(36).toUpperCase()
  );

app.post('/api/keys', (req, res) => {
  const { durationDays } = req.body;
  const newKey = {
    key: generateKey(),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000).toISOString(),
    isActive: true,
    hwid: null
  };
  keys.push(newKey);
  res.json({ message: 'Key olusturuldu', key: newKey });
});

app.get('/api/keys', (req, res) => {
  res.json(keys);
});

app.delete('/api/keys/:key', (req, res) => {
  const before = keys.length;
  keys = keys.filter(k => k.key !== req.params.key);
  if (keys.length === before)
    return res.status(404).json({ error: 'Key bulunamadi' });
  res.json({ message: 'Key silindi' });
});

app.patch('/api/keys/:key/toggle', (req, res) => {
  const keyRecord = keys.find(k => k.key === req.params.key);
  if (!keyRecord)
    return res.status(404).json({ error: 'Key bulunamadi' });
  keyRecord.isActive = !keyRecord.isActive;
  res.json({ message: 'Key durumu guncellendi', key: keyRecord });
});

// ── VERIFY ────────────────────────────────────────────

app.post('/api/verify', (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid)
    return res.status(400).json({ error: 'Key ve HWID gerekli' });

  const keyRecord = keys.find(k => k.key === key);
  if (!keyRecord)
    return res.status(404).json({ error: 'Gecersiz Key' });
  if (!keyRecord.isActive)
    return res.status(403).json({ error: 'Bu Key devre disi birakilmis' });
  if (new Date() > new Date(keyRecord.expiresAt))
    return res.status(403).json({ error: 'Bu Key suresi dolmus' });

  if (!keyRecord.hwid) {
    keyRecord.hwid = hwid;
  } else if (keyRecord.hwid !== hwid) {
    return res.status(403).json({ error: 'Bu Key baska bir cihaza kayitli' });
  }

  res.json({ message: 'Dogrulama Basarili', status: 'OK', expiresAt: keyRecord.expiresAt });
});

// ── START ─────────────────────────────────────────────

app.listen(PORT, () => {
  console.log('Sunucu http://localhost:' + PORT + ' adresinde calisiyor');
});

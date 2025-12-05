require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const xlsx = require('xlsx');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const nodemailer = require('nodemailer');
const dns = require('dns');

// --- CLOUDINARY ---
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
const port = process.env.PORT || 3000;

// --- CONFIGURAÇÃO DE EMAIL (Serverless Friendly) ---
const customLookup = (hostname, options, callback) => {
    dns.lookup(hostname, { family: 4 }, (err, address, family) => {
        if (err) return callback(err);
        callback(null, address, family);
    });
};

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  lookup: customLookup
});

// --- MIDDLEWARES ---
app.use(cors({
    origin: ['https://tamura-frontend.vercel.app', 'http://localhost:5173'],
    credentials: true
}));
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" })); 
app.use(bodyParser.json());

// --- CONFIGURAÇÃO DE UPLOAD (CLOUDINARY) ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'tamura-eventos',
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
  },
});
const upload = multer({ storage: storage });

// --- AUTH MIDDLEWARE ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

const sanitize = (value) => (value === '' ? null : value);

// --- BANCO DE DADOS ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } 
});
const query = (text, params) => pool.query(text, params);

// --- PLANOS PADRÃO ---
const DEFAULT_PLANS = [
  { id: '50cc', name: '50cc', price: 80, limit_cat: 1, allowed: JSON.stringify(['50cc']), description: 'Exclusivo para categoria 50cc' },
  { id: 'fem', name: 'Feminino', price: 80, limit_cat: 1, allowed: JSON.stringify(['Feminino']), description: 'Exclusivo para categoria Feminino' },
  { id: '65cc', name: '65cc', price: 130, limit_cat: 1, allowed: JSON.stringify(['65cc']), description: 'Exclusivo para categoria 65cc' },
  { id: 'p1', name: '1 Categoria', price: 130, limit_cat: 1, allowed: null, description: 'Inscrição para uma única bateria' },
  { id: 'kids_combo', name: '65cc + 50cc', price: 170, limit_cat: 2, allowed: JSON.stringify(['50cc', '65cc']), description: 'Combo Promocional Kids' },
  { id: 'p2', name: '2 Categorias', price: 200, limit_cat: 2, allowed: null, description: 'Desconto para correr duas baterias' },
  { id: 'full', name: 'Full Pass', price: 230, limit_cat: 99, allowed: null, description: 'Acesso total a todas as categorias' },
];

// --- INICIALIZAÇÃO DB ---
const initDb = async () => {
  try {
    await query(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
    await query(`INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, ['pix_key', '']);

    await query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT, email TEXT UNIQUE, phone TEXT, cpf TEXT UNIQUE, bike_number TEXT, chip_id TEXT, password TEXT, role TEXT DEFAULT 'user', birth_date DATE, reset_token TEXT, reset_expires TIMESTAMP)`);

    await query(`CREATE TABLE IF NOT EXISTS stages (id SERIAL PRIMARY KEY, name TEXT, location TEXT, date TEXT, image_url TEXT, status TEXT DEFAULT 'upcoming', batch_name TEXT DEFAULT 'Lote Inicial')`);

    await query(`CREATE TABLE IF NOT EXISTS plans (id TEXT PRIMARY KEY, name TEXT, price REAL, limit_cat INTEGER, allowed TEXT, description TEXT)`);

    // Verifica e insere planos faltantes
    for (const plan of DEFAULT_PLANS) {
        await query(
          `INSERT INTO plans (id, name, price, limit_cat, allowed, description) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
          [plan.id, plan.name, plan.price, plan.limit_cat, plan.allowed, plan.description]
        );
    }

    await query(`CREATE TABLE IF NOT EXISTS stage_prices (stage_id INTEGER, plan_id TEXT, price REAL, PRIMARY KEY (stage_id, plan_id), FOREIGN KEY(stage_id) REFERENCES stages(id) ON DELETE CASCADE, FOREIGN KEY(plan_id) REFERENCES plans(id))`);

    await query(`CREATE TABLE IF NOT EXISTS results (id SERIAL PRIMARY KEY, stage_id INTEGER, position INTEGER, epc TEXT, pilot_number TEXT, pilot_name TEXT, category TEXT, laps TEXT, total_time TEXT, last_lap TEXT, diff_first TEXT, diff_prev TEXT, best_lap TEXT, avg_speed TEXT, points INTEGER, FOREIGN KEY(stage_id) REFERENCES stages(id) ON DELETE CASCADE)`);

    await query(`CREATE TABLE IF NOT EXISTS registrations (id SERIAL PRIMARY KEY, user_id INTEGER, stage_id INTEGER, pilot_name TEXT, pilot_number TEXT, plan_name TEXT, categories TEXT, total_price REAL, status TEXT DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(stage_id) REFERENCES stages(id) ON DELETE CASCADE)`);

    const adminEmail = '10tamura@gmail.com'; 
    const adminUser = await query("SELECT * FROM users WHERE email = $1", [adminEmail]);
    if (adminUser.rows.length === 0) {
      const hashedPassword = bcrypt.hashSync('1234', 10);
      await query(`INSERT INTO users (name, email, phone, cpf, bike_number, password, role) VALUES ($1, $2, $3, $4, $5, $6, 'admin')`, ['Admin Tamura', adminEmail, '999999999', '00000000000', '00', hashedPassword]);
    }
  } catch (err) { console.error("Erro DB:", err); }
};
initDb();

const getPointsByPosition = (position) => {
  const pointsMap = { 1: 25, 2: 22, 3: 20, 4: 18, 5: 16, 6: 15, 7: 14, 8: 13, 9: 12, 10: 11, 11: 10, 12: 9, 13: 8, 14: 7, 15: 6, 16: 5, 17: 4, 18: 3, 19: 2, 20: 1 };
  return pointsMap[position] || 0;
};

// =====================================================
// ROTAS
// =====================================================

app.get('/', (req, res) => res.send('Tamura API Online'));

// --- SETTINGS ---
app.get('/api/settings/:key', async (req, res) => {
    try { const r = await query("SELECT value FROM settings WHERE key = $1", [req.params.key]); res.json({ value: r.rows[0]?.value || '' }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/settings/:key', authenticateToken, async (req, res) => {
    try { await query("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2", [req.params.key, req.body.value]); res.json({ message: "OK" }); } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- AUTH ---
app.post('/register', async (req, res) => {
  const { name, email, phone, cpf, bike_number, password, birth_date } = req.body;
  if (!name || !email || !cpf || !password) return res.status(400).json({ error: "Dados incompletos" });
  try {
      const hashed = await bcrypt.hash(password, 10);
      const r = await query(`INSERT INTO users (name, email, phone, cpf, bike_number, password, role, birth_date) VALUES ($1, $2, $3, $4, $5, $6, 'user', $7) RETURNING id`, [name, email, phone, cpf, bike_number, hashed, sanitize(birth_date)]);
      res.json({ message: "Sucesso", userId: r.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.code === '23505' ? "Email/CPF já existe" : e.message }); }
});

app.post('/login', async (req, res) => {
  try {
      const r = await query(`SELECT * FROM users WHERE (email = $1 OR name = $1 OR phone = $1)`, [req.body.identifier]);
      const user = r.rows[0];
      if (!user || !await bcrypt.compare(req.body.password, user.password)) return res.status(401).json({ error: "Credenciais inválidas" });
      const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
      res.json({ id: user.id, name: user.name, role: user.role, bike_number: user.bike_number, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- STAGES ---
app.get('/api/stages', async (req, res) => {
  try { const r = await query("SELECT * FROM stages ORDER BY date ASC"); res.json(r.rows); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/stages', authenticateToken, upload.single('image'), async (req, res) => {
  const img = req.file ? req.file.path : null;
  const client = await pool.connect();
  try {
      await client.query('BEGIN');
      const r = await client.query(`INSERT INTO stages (name, location, date, image_url, batch_name) VALUES ($1, $2, $3, $4, 'Lote Inicial') RETURNING id`, [req.body.name, req.body.location, req.body.date, img]);
      for (const p of DEFAULT_PLANS) await client.query("INSERT INTO stage_prices (stage_id, plan_id, price) VALUES ($1, $2, $3)", [r.rows[0].id, p.id, p.price]);
      await client.query('COMMIT');
      res.json({ id: r.rows[0].id, message: "Criado!" });
  } catch (e) { await client.query('ROLLBACK'); res.status(500).json({ error: e.message }); } finally { client.release(); }
});

app.put('/api/stages/:id', authenticateToken, upload.single('image'), async (req, res) => {
    let sql = `UPDATE stages SET name = $1, location = $2, date = $3 WHERE id = $4`;
    let params = [req.body.name, req.body.location, req.body.date, req.params.id];
    if (req.file) { sql = `UPDATE stages SET name = $1, location = $2, date = $3, image_url = $4 WHERE id = $5`; params = [req.body.name, req.body.location, req.body.date, req.file.path, req.params.id]; }
    try { await query(sql, params); res.json({ message: "Atualizado!" }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/stages/:id', authenticateToken, async (req, res) => {
    try { await query("DELETE FROM stages WHERE id = $1", [req.params.id]); res.json({ message: "Deletado" }); } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- USERS ---
app.get('/api/users', authenticateToken, async (req, res) => {
  try { const r = await query(`SELECT id, name, email, phone, cpf, bike_number, chip_id, role, birth_date FROM users ORDER BY name ASC`); res.json(r.rows); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/:id', authenticateToken, async (req, res) => {
    try { const r = await query(`SELECT id, name, email, phone, cpf, bike_number, chip_id, role, birth_date FROM users WHERE id = $1`, [req.params.id]); res.json(r.rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const { name, email, phone, bike_number, chip_id, role, birth_date } = req.body;
    try { await query(`UPDATE users SET name=$1, email=$2, phone=$3, bike_number=$4, chip_id=$5, role=$6, birth_date=$7 WHERE id=$8`, [name, email, phone, bike_number, chip_id, role, sanitize(birth_date), req.params.id]); res.json({ message: "Atualizado" }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
    try { await query("DELETE FROM users WHERE id = $1", [req.params.id]); res.json({ message: "Deletado" }); } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- PREÇOS ---
app.get('/api/stages/:id/prices', async (req, res) => {
    try {
        const plans = await query(`SELECT p.id, p.name, p.limit_cat, p.allowed, p.description, COALESCE(sp.price, p.price) as price FROM plans p LEFT JOIN stage_prices sp ON p.id = sp.plan_id AND sp.stage_id = $1`, [req.params.id]);
        const stage = await query("SELECT batch_name FROM stages WHERE id = $1", [req.params.id]);
        const formatted = plans.rows.map(r => ({ ...r, allowed: r.allowed ? JSON.parse(r.allowed) : null }));
        res.json({ batch_name: stage.rows[0]?.batch_name || 'Lote Inicial', plans: formatted });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/stages/:id/prices', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query("UPDATE stages SET batch_name = $1 WHERE id = $2", [req.body.batch_name, req.params.id]);
        for (const p of req.body.plans) {
            await client.query(`INSERT INTO stage_prices (stage_id, plan_id, price) VALUES ($1, $2, $3) ON CONFLICT (stage_id, plan_id) DO UPDATE SET price = $3`, [req.params.id, p.id, p.price]);
        }
        await client.query('COMMIT');
        res.json({ message: "Preços atualizados" });
    } catch (e) { await client.query('ROLLBACK'); res.status(500).json({ error: e.message }); } finally { client.release(); }
});

// --- INSCRIÇÕES ---
app.get('/api/registrations/stage/:stageId', authenticateToken, async (req, res) => {
    try { const r = await query(`SELECT r.*, u.phone, u.cpf, u.email FROM registrations r LEFT JOIN users u ON r.user_id = u.id WHERE r.stage_id = $1 ORDER BY r.pilot_name ASC`, [req.params.stageId]); res.json(r.rows); } catch (e) { res.status(500).json({ error: e.message }); }
});

// ROTA ADICIONADA: Inscrições por usuário (para o UserDashboard)
app.get('/api/registrations/user/:userId', authenticateToken, async (req, res) => {
    try { const r = await query(`SELECT * FROM registrations WHERE user_id = $1 ORDER BY created_at DESC`, [req.params.userId]); res.json(r.rows); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/registrations', authenticateToken, async (req, res) => {
    const { user_id, stage_id, pilot_name, pilot_number, plan_name, categories, total_price } = req.body;
    try {
        await query(`INSERT INTO registrations (user_id, stage_id, pilot_name, pilot_number, plan_name, categories, total_price) VALUES ($1, $2, $3, $4, $5, $6, $7)`, [user_id, stage_id, pilot_name, pilot_number, plan_name, categories.join(', '), total_price]);
        res.json({ message: "Inscrição realizada!" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/registrations/:id/status', authenticateToken, async (req, res) => {
    try { await query("UPDATE registrations SET status = $1 WHERE id = $2", [req.body.status, req.params.id]); res.json({ message: "Status atualizado" }); } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- RESULTADOS & RANKING ---
app.get('/api/stages/:id/categories-status', async (req, res) => {
    try { const r = await query(`SELECT DISTINCT category FROM results WHERE stage_id = $1`, [req.params.id]); res.json(r.rows.map(row => row.category)); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/stages/:id/results/:category', async (req, res) => {
    try { const r = await query(`SELECT * FROM results WHERE stage_id = $1 AND category = $2 ORDER BY position ASC`, [req.params.id, req.params.category]); res.json(r.rows); } catch (e) { res.status(500).json({ error: e.message }); }
});

// ROTA ADICIONADA: Ranking Geral
app.get('/api/standings/overall', async (req, res) => {
    try { const r = await query(`SELECT pilot_name, pilot_number, category, SUM(points) as points FROM results GROUP BY category, pilot_name, pilot_number ORDER BY category ASC, points DESC`); res.json(r.rows); } catch (e) { res.status(500).json({ error: e.message }); }
});

// ROTA ADICIONADA: Ranking por Etapa (usado na tabela)
app.get('/api/stages/:id/standings', async (req, res) => {
    try { const r = await query(`SELECT * FROM results WHERE stage_id = $1 ORDER BY category ASC, position ASC`, [req.params.id]); res.json(r.rows); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/stages/:id/upload/:category', authenticateToken, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Sem arquivo" });
  const client = await pool.connect();
  try {
    let workbook;
    if (req.file.path.startsWith('http')) {
        const resp = await fetch(req.file.path);
        const buff = await resp.arrayBuffer();
        workbook = xlsx.read(new Uint8Array(buff), { type: 'array' });
    } else { workbook = xlsx.readFile(req.file.path); }

    const data = xlsx.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]], { header: 1, defval: "" });
    let headerFound = false;
    const results = [];

    data.forEach(row => {
        if (!headerFound) { if (row[0] && (row[0].toString().trim() === 'P' || row[0].toString().trim() === 'Pos')) headerFound = true; return; }
        const pos = parseInt(row[0]);
        if (!isNaN(pos)) {
            results.push({
                stage_id: req.params.id, position: pos, epc: row[2]||'', pilot_number: row[3]||'', pilot_name: row[4]||'Desconhecido', category: req.params.category, laps: row[8]||'', total_time: row[9]||'', last_lap: row[12]||'', diff_first: row[13]||'', diff_prev: row[16]||'', best_lap: row[18]||'', avg_speed: row[24]||'', points: getPointsByPosition(pos)
            });
        }
    });

    await client.query('BEGIN');
    await client.query(`DELETE FROM results WHERE stage_id = $1 AND category = $2`, [req.params.id, req.params.category]);
    for (const r of results) {
        await client.query(`INSERT INTO results (stage_id, position, epc, pilot_number, pilot_name, category, laps, total_time, last_lap, diff_first, diff_prev, best_lap, avg_speed, points) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, 
        [r.stage_id, r.position, r.epc, r.pilot_number, r.pilot_name, r.category, r.laps, r.total_time, r.last_lap, r.diff_first, r.diff_prev, r.best_lap, r.avg_speed, r.points]);
    }
    await client.query('COMMIT');
    res.json({ message: "OK", data: results });
  } catch (e) { await client.query('ROLLBACK'); console.error(e); res.status(500).json({ error: "Erro processamento" }); } finally { client.release(); }
});

// ROTA ADICIONADA: Backup do Admin (Adaptado para Postgres - Dump simples)
// Nota: Em produção real, use pg_dump. Aqui é apenas um placeholder para não quebrar o frontend.
app.get('/api/admin/backup', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    // Como estamos no Postgres, não existe um arquivo .sqlite para baixar.
    // Retornamos um JSON com dados críticos como "backup".
    try {
        const users = await query("SELECT * FROM users");
        const registrations = await query("SELECT * FROM registrations");
        const results = await query("SELECT * FROM results");
        const backupData = { users: users.rows, registrations: registrations.rows, results: results.rows };
        
        res.setHeader('Content-Disposition', 'attachment; filename=backup.json');
        res.setHeader('Content-Type', 'application/json');
        res.send(JSON.stringify(backupData, null, 2));
    } catch(e) { res.status(500).json({error: e.message}); }
});

// =====================================================
// ROTAS DE RECUPERAÇÃO DE SENHA (Faltavam estas!)
// =====================================================

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const userResult = await query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];

    if (!user) {
      // Por segurança, não informamos se o email não existe, mas logamos
      return res.json({ message: "Se o email existir, enviamos um link." });
    }

    // Gera token simples e expiração (1 hora)
    const token = crypto.randomBytes(20).toString('hex');
    const now = new Date();
    now.setHours(now.getHours() + 1);

    await query("UPDATE users SET reset_token = $1, reset_expires = $2 WHERE id = $3", [token, now, user.id]);

    // Envia o email
    await sendEmail(
      email,
      "Recuperação de Senha - Tamura Eventos",
      `Seu token de recuperação é: ${token}\n\nCopie e cole este token na página de redefinição ou use o link: https://tamura-frontend.vercel.app/reset-password`
    );

    res.json({ message: "Email enviado!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao processar recuperação." });
  }
});

app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    // Busca usuário com token válido e que não expirou
    const result = await query(
      "SELECT * FROM users WHERE reset_token = $1 AND reset_expires > NOW()", 
      [token]
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: "Token inválido ou expirado." });
    }

    // Hash da nova senha
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Atualiza senha e limpa o token
    await query(
      "UPDATE users SET password = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2",
      [hashedPassword, user.id]
    );

    res.json({ message: "Senha alterada com sucesso!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao redefinir senha." });
  }
});

module.exports = app;
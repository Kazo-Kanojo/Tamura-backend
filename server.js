require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const xlsx = require('xlsx');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const dns = require('dns');

const app = express();
const port = process.env.PORT || 3000;

// =====================================================
// 1. CONFIGURAÇÕES (EMAIL, UPLOAD, SEGURANÇA)
// =====================================================

// Correção IPv6 para E-mail
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
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  lookup: customLookup
});

const sendEmail = async (to, subject, text) => {
  try {
    await transporter.sendMail({ from: `"Tamura Eventos" <${process.env.EMAIL_USER}>`, to, subject, text });
    console.log(`Email enviado para ${to}`);
  } catch (error) {
    console.error("Erro email:", error);
  }
};

// Segurança
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Muitas tentativas. Bloqueado por 15 min." },
  standardHeaders: true, legacyHeaders: false,
});

// Upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => { if (!fs.existsSync('uploads')) fs.mkdirSync('uploads'); cb(null, 'uploads/'); },
  filename: (req, file, cb) => { const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9); cb(null, uniqueSuffix + path.extname(file.originalname)); }
});
const fileFilter = (req, file, cb) => {
  const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.ms-excel', 'text/csv', 'application/csv'];
  if (allowed.includes(file.mimetype)) cb(null, true); else cb(new Error('Tipo inválido.'), false);
};
const upload = multer({ storage, fileFilter });

// Middlewares
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" })); 
app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static('uploads')); 

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

// =====================================================
// 2. BANCO DE DADOS
// =====================================================

const db = new sqlite3.Database('./database.sqlite');

const DEFAULT_PLANS = [
  { id: '50cc',       name: '50cc',          price: 80,  limit_cat: 1,  allowed: JSON.stringify(['50cc']), description: 'Exclusivo para categoria 50cc' },
  { id: 'fem',        name: 'Feminino',      price: 80,  limit_cat: 1,  allowed: JSON.stringify(['Feminino']), description: 'Exclusivo para categoria Feminino' },
  { id: '65cc',       name: '65cc',          price: 130, limit_cat: 1,  allowed: JSON.stringify(['65cc']), description: 'Exclusivo para categoria 65cc' },
  { id: 'p1',         name: '1 Categoria',   price: 130, limit_cat: 1,  allowed: null, description: 'Inscrição para uma única bateria' },
  { id: 'kids_combo', name: '65cc + 50cc',   price: 170, limit_cat: 2,  allowed: JSON.stringify(['50cc', '65cc']), description: 'Combo Promocional Kids' },
  { id: 'p2',         name: '2 Categorias',  price: 200, limit_cat: 2,  allowed: null, description: 'Desconto para correr duas baterias' },
  { id: 'full',       name: 'Full Pass',     price: 230, limit_cat: 99, allowed: null, description: 'Acesso total a todas as categorias' },
];

db.serialize(() => {
  // Configurações Globais
  db.run(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('pix_key', '')`);

  // Usuários
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, phone TEXT, cpf TEXT UNIQUE, bike_number TEXT, chip_id TEXT, password TEXT, role TEXT DEFAULT 'user', reset_token TEXT, reset_expires DATETIME)`);
  db.run("ALTER TABLE users ADD COLUMN chip_id TEXT", (err) => {}); 
  db.run("ALTER TABLE users ADD COLUMN reset_token TEXT", (err) => {}); 
  db.run("ALTER TABLE users ADD COLUMN reset_expires DATETIME", (err) => {}); 

  // Etapas (Stages) - Com Batch Name (Nome do Lote)
  db.run(`CREATE TABLE IF NOT EXISTS stages (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, location TEXT, date TEXT, image_url TEXT, status TEXT DEFAULT 'upcoming', batch_name TEXT DEFAULT 'Lote Inicial')`);
  db.run("ALTER TABLE stages ADD COLUMN image_url TEXT", (err) => {}); 
  db.run("ALTER TABLE stages ADD COLUMN batch_name TEXT DEFAULT 'Lote Inicial'", (err) => {}); 

  // Planos Base (Templates)
  db.run(`CREATE TABLE IF NOT EXISTS plans (id TEXT PRIMARY KEY, name TEXT, price REAL, limit_cat INTEGER, allowed TEXT, description TEXT)`);
  db.get("SELECT count(*) as count FROM plans", (err, row) => {
    if (row && row.count === 0) {
      const stmt = db.prepare("INSERT INTO plans (id, name, price, limit_cat, allowed, description) VALUES (?, ?, ?, ?, ?, ?)");
      DEFAULT_PLANS.forEach(plan => {
        stmt.run(plan.id, plan.name, plan.price, plan.limit_cat, plan.allowed, plan.description);
      });
      stmt.finalize();
    }
  });

  // Preços por Etapa (NOVA TABELA)
  db.run(`CREATE TABLE IF NOT EXISTS stage_prices (
      stage_id INTEGER,
      plan_id TEXT,
      price REAL,
      PRIMARY KEY (stage_id, plan_id),
      FOREIGN KEY(stage_id) REFERENCES stages(id),
      FOREIGN KEY(plan_id) REFERENCES plans(id)
  )`);

  // Resultados e Inscrições
  db.run(`CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY AUTOINCREMENT, stage_id INTEGER, position INTEGER, epc TEXT, pilot_number TEXT, pilot_name TEXT, category TEXT, laps TEXT, total_time TEXT, last_lap TEXT, diff_first TEXT, diff_prev TEXT, best_lap TEXT, avg_speed TEXT, points INTEGER, FOREIGN KEY(stage_id) REFERENCES stages(id))`);
  db.run(`CREATE TABLE IF NOT EXISTS registrations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, stage_id INTEGER, pilot_name TEXT, pilot_number TEXT, plan_name TEXT, categories TEXT, total_price REAL, status TEXT DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(stage_id) REFERENCES stages(id))`);

  // Admin Padrão
  const adminEmail = '10tamura@gmail.com'; 
  const rawPass = '1234';
  db.get("SELECT * FROM users WHERE email = ?", [adminEmail], (err, row) => {
    if (!row) {
      const hashedPassword = bcrypt.hashSync(rawPass, 10);
      db.run(`INSERT INTO users (name, email, phone, cpf, bike_number, password, role) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        ['Admin Tamura', adminEmail, '999999999', '00000000000', '00', hashedPassword, 'admin']);
    }
  });
});

const getPointsByPosition = (position) => {
  const pointsMap = { 1: 25, 2: 22, 3: 20, 4: 18, 5: 16, 6: 15, 7: 14, 8: 13, 9: 12, 10: 11, 11: 10, 12: 9, 13: 8, 14: 7, 15: 6, 16: 5, 17: 4, 18: 3, 19: 2, 20: 1 };
  return pointsMap[position] || 0;
};

// =====================================================
// ROTAS API
// =====================================================

// --- BACKUP ---
app.get('/api/admin/backup', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Acesso negado." });
    const dbPath = path.join(__dirname, 'database.sqlite');
    res.download(dbPath, 'backup_tamura.sqlite', (err) => { if (err) console.error("Erro download:", err); });
});

// --- SETTINGS (Chave PIX Global) ---
app.get('/api/settings/:key', (req, res) => {
    db.get("SELECT value FROM settings WHERE key = ?", [req.params.key], (err, row) => { if (err) return res.status(500).json({ error: err.message }); res.json({ value: row ? row.value : '' }); });
});
app.put('/api/settings/:key', authenticateToken, (req, res) => {
    db.run("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", [req.params.key, req.body.value], function(err) { if (err) return res.status(500).json({ error: err.message }); res.json({ message: "Atualizado!" }); });
});

// --- AUTH ---
app.post('/register', async (req, res) => {
  const { name, email, phone, cpf, bike_number, password } = req.body;
  if (!name || !email || !cpf || !password) return res.status(400).json({ error: "Obrigatório" });
  try {
      const hashedPassword = await bcrypt.hash(password, 10);
      db.run(`INSERT INTO users (name, email, phone, cpf, bike_number, password, role) VALUES (?, ?, ?, ?, ?, ?, 'user')`, 
        [name, email, phone, cpf, bike_number, hashedPassword], function(err) {
          if (err) { if (err.message.includes('UNIQUE')) return res.status(400).json({ error: "Email/CPF duplicado." }); return res.status(500).json({ error: err.message }); }
          res.json({ message: "Sucesso!", userId: this.lastID });
      });
  } catch (e) { res.status(500).json({ error: "Erro senha" }); }
});

app.post('/login', loginLimiter, (req, res) => {
  const { identifier, password } = req.body;
  db.get(`SELECT * FROM users WHERE (email = ? OR name = ? OR phone = ?)`, [identifier, identifier, identifier], async (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: "Não encontrado." });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Senha incorreta." });
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ id: user.id, name: user.name, role: user.role, bike_number: user.bike_number, token });
  });
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (!user) return res.status(404).json({ error: "E-mail não encontrado." });
        const token = crypto.randomBytes(20).toString('hex');
        const now = new Date(); now.setHours(now.getHours() + 1);
        db.run("UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?", [token, now.toISOString(), user.id], async (err) => {
            if (err) return res.status(500).json({ error: "Erro banco" });
            await sendEmail(email, "Recuperação - Tamura Eventos", `Seu código de recuperação é: ${token}`);
            res.json({ message: "Token enviado." });
        });
    });
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    db.get("SELECT * FROM users WHERE reset_token = ? AND reset_expires > ?", [token, new Date().toISOString()], async (err, user) => {
        if (!user) return res.status(400).json({ error: "Token inválido/expirado." });
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run("UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?", [hashedPassword, user.id], (err) => {
            if (err) return res.status(500).json({ error: "Erro ao salvar." });
            res.json({ message: "Senha alterada!" });
        });
    });
});

// --- PLANOS GERAIS ---
app.get('/api/plans', (req, res) => {
  db.all("SELECT * FROM plans", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows.map(r => ({ ...r, allowed: r.allowed ? JSON.parse(r.allowed) : null })));
  });
});

// --- USUÁRIOS ---
app.get('/api/users', authenticateToken, (req, res) => {
  db.all(`SELECT id, name, email, phone, cpf, bike_number, chip_id, role FROM users ORDER BY name ASC`, [], (err, rows) => { if (err) return res.status(500).json({ error: err.message }); res.json(rows); });
});
app.get('/api/users/:id', authenticateToken, (req, res) => {
    if (req.user.id != req.params.id && req.user.role !== 'admin') return res.status(403).json({ error: "Acesso negado." });
    db.get("SELECT id, name, email, phone, cpf, bike_number, chip_id, role FROM users WHERE id = ?", [req.params.id], (err, row) => { if (err) return res.status(500).json({ error: err.message }); res.json(row||{}); });
});
app.put('/api/users/:id', authenticateToken, (req, res) => {
    const { name, email, phone, bike_number, chip_id, role } = req.body;
    db.run(`UPDATE users SET name = ?, email = ?, phone = ?, bike_number = ?, chip_id = ?, role = ? WHERE id = ?`, [name, email, phone, bike_number, chip_id, role, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message }); res.json({ message: "Atualizado!" });
    });
});
app.delete('/api/users/:id', authenticateToken, (req, res) => {
    db.run("DELETE FROM users WHERE id = ?", [req.params.id], function(err) { if (err) return res.status(500).json({ error: err.message }); res.json({ message: "Excluído." }); });
});

// --- ETAPAS (COM CRIAÇÃO DE PREÇOS AUTOMÁTICA) ---
app.get('/api/stages', (req, res) => {
  db.all("SELECT * FROM stages ORDER BY date ASC", [], (err, rows) => { if (err) return res.status(500).json({ error: err.message }); res.json(rows); });
});

app.post('/api/stages', authenticateToken, upload.single('image'), (req, res) => {
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
  db.run(`INSERT INTO stages (name, location, date, image_url, batch_name) VALUES (?, ?, ?, ?, 'Lote Inicial')`, 
    [req.body.name, req.body.location, req.body.date, imageUrl], 
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      
      const newStageId = this.lastID;
      // Cria preços para esta nova etapa baseados no padrão
      const stmt = db.prepare("INSERT INTO stage_prices (stage_id, plan_id, price) VALUES (?, ?, ?)");
      DEFAULT_PLANS.forEach(p => stmt.run(newStageId, p.id, p.price));
      stmt.finalize();

      res.json({ id: newStageId, message: "Criado!" });
  });
});

app.put('/api/stages/:id', authenticateToken, upload.single('image'), (req, res) => {
    let query = `UPDATE stages SET name = ?, location = ?, date = ? WHERE id = ?`;
    let params = [req.body.name, req.body.location, req.body.date, req.params.id];
    if (req.file) { query = `UPDATE stages SET name = ?, location = ?, date = ?, image_url = ? WHERE id = ?`; params = [req.body.name, req.body.location, req.body.date, `/uploads/${req.file.filename}`, req.params.id]; }
    db.run(query, params, function(err) { if (err) return res.status(500).json({ error: err.message }); res.json({ message: "Atualizado!" }); });
});

app.delete('/api/stages/:id', authenticateToken, (req, res) => {
    db.get("SELECT image_url FROM stages WHERE id = ?", [req.params.id], (err, row) => {
        if (row && row.image_url) { const filePath = path.join(__dirname, row.image_url); fs.unlink(filePath, (err) => {}); }
        db.serialize(() => {
            db.run("DELETE FROM stage_prices WHERE stage_id = ?", [req.params.id]); // Limpa preços
            db.run("DELETE FROM results WHERE stage_id = ?", [req.params.id]);
            db.run("DELETE FROM registrations WHERE stage_id = ?", [req.params.id]);
            db.run("DELETE FROM stages WHERE id = ?", [req.params.id], function(err) {
                if (err) return res.status(500).json({ error: err.message }); res.json({ message: "Excluído." });
            });
        });
    });
});

// --- PREÇOS ESPECÍFICOS POR ETAPA (NOVO) ---
app.get('/api/stages/:id/prices', (req, res) => {
    const stageId = req.params.id;
    const query = `
        SELECT p.id, p.name, p.limit_cat, p.allowed, p.description, 
               COALESCE(sp.price, p.price) as price 
        FROM plans p
        LEFT JOIN stage_prices sp ON p.id = sp.plan_id AND sp.stage_id = ?
    `;
    db.all(query, [stageId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        db.get("SELECT batch_name FROM stages WHERE id = ?", [stageId], (err, stage) => {
            const batchName = stage ? stage.batch_name : 'Lote Inicial';
            const formattedPlans = rows.map(r => ({ ...r, allowed: r.allowed ? JSON.parse(r.allowed) : null }));
            res.json({ batch_name: batchName, plans: formattedPlans });
        });
    });
});

app.put('/api/stages/:id/prices', authenticateToken, (req, res) => {
    const stageId = req.params.id;
    const { batch_name, plans } = req.body;
    
    db.run("UPDATE stages SET batch_name = ? WHERE id = ?", [batch_name, stageId], (err) => {
        if (err) return res.status(500).json({ error: "Erro lote" });
        const stmt = db.prepare("INSERT OR REPLACE INTO stage_prices (stage_id, plan_id, price) VALUES (?, ?, ?)");
        plans.forEach(p => stmt.run(stageId, p.id, p.price));
        stmt.finalize();
        res.json({ message: "Preços atualizados!" });
    });
});

// --- INSCRIÇÕES ---
app.post('/api/registrations', authenticateToken, (req, res) => {
  const { user_id, stage_id, pilot_name, pilot_number, plan_name, categories, total_price } = req.body;
  const categoriesStr = Array.isArray(categories) ? categories.join(', ') : categories;
  db.run(`INSERT INTO registrations (user_id, stage_id, pilot_name, pilot_number, plan_name, categories, total_price) VALUES (?, ?, ?, ?, ?, ?, ?)`, [user_id, stage_id, pilot_name, pilot_number, plan_name, categoriesStr, total_price], function(err) {
      if (err) return res.status(500).json({ error: err.message }); res.json({ message: "Inscrição OK!", registrationId: this.lastID });
  });
});
app.get('/api/registrations/user/:userId', authenticateToken, (req, res) => {
    if (req.user.id != req.params.userId && req.user.role !== 'admin') return res.status(403).json({ error: "Acesso negado." });
    db.all(`SELECT r.*, s.name as stage_name, s.date as stage_date, s.image_url FROM registrations r JOIN stages s ON r.stage_id = s.id WHERE r.user_id = ? ORDER BY r.created_at DESC`, [req.params.userId], (err, rows) => { if (err) return res.status(500).json({ error: err.message }); res.json(rows); });
});
app.get('/api/registrations/stage/:stageId', authenticateToken, (req, res) => {
    db.all(`SELECT r.*, u.phone, u.cpf, u.email FROM registrations r LEFT JOIN users u ON r.user_id = u.id WHERE r.stage_id = ? ORDER BY r.pilot_name ASC`, [req.params.stageId], (err, rows) => { if (err) return res.status(500).json({ error: err.message }); res.json(rows); });
});
app.put('/api/registrations/:id/status', authenticateToken, (req, res) => {
    const { status } = req.body;
    db.run(`UPDATE registrations SET status = ? WHERE id = ?`, [status, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Status atualizado!" });
        if (status === 'paid') {
            db.get(`SELECT r.*, u.email, s.name as stage_name FROM registrations r JOIN users u ON r.user_id = u.id JOIN stages s ON r.stage_id = s.id WHERE r.id = ?`, [req.params.id], async (err, row) => {
                if (!err && row && row.email) {
                    await sendEmail(
                        row.email, 
                        "Inscrição Confirmada - Tamura Eventos", 
                        `Olá ${row.pilot_name},\n\nSua inscrição para a etapa "${row.stage_name}" foi CONFIRMADA!\n\nPrepare sua moto e boa prova!\nEquipe Tamura Eventos`
                    );
                }
            });
        }
    });
});

// --- RESULTADOS ---
app.get('/api/stages/:id/categories-status', (req, res) => { db.all(`SELECT DISTINCT category FROM results WHERE stage_id = ?`, [req.params.id], (err, rows) => { if (err) return res.status(500).json({ error: err.message }); res.json(rows.map(r => r.category)); }); });
app.get('/api/stages/:id/results/:category', (req, res) => { db.all(`SELECT * FROM results WHERE stage_id = ? AND category = ? ORDER BY position ASC`, [req.params.id, req.params.category], (err, rows) => { if (err) return res.status(500).json({ error: err.message }); res.json(rows); }); });
app.post('/api/stages/:id/upload/:category', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Sem arquivo." });
  try {
    const workbook = xlsx.readFile(req.file.path);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const data = xlsx.utils.sheet_to_json(sheet, { header: 1, defval: "" });
    const resultsToSave = [];
    let headerFound = false;
    data.forEach((row) => {
      if (!headerFound) { if (row[0] && (row[0].toString().trim() === 'P' || row[0].toString().trim() === 'Pos')) headerFound = true; return; }
      const pos = parseInt(row[0]);
      if (!isNaN(pos)) {
        resultsToSave.push({
          stage_id: req.params.id, position: pos, epc: row[2] || '', pilot_number: row[3] || '', pilot_name: row[4] || 'Desconhecido',
          category: req.params.category, laps: row[8] || '', total_time: row[9] || '', last_lap: row[12] || '',
          diff_first: row[13] || '', diff_prev: row[16] || '', best_lap: row[18] || '', 
          avg_speed: row[24] || '', 
          points: getPointsByPosition(pos)
        });
      }
    });
    db.serialize(() => {
      db.run(`DELETE FROM results WHERE stage_id = ? AND category = ?`, [req.params.id, req.params.category]);
      const stmt = db.prepare(`INSERT INTO results (stage_id, position, epc, pilot_number, pilot_name, category, laps, total_time, last_lap, diff_first, diff_prev, best_lap, avg_speed, points) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      resultsToSave.forEach(r => { stmt.run(r.stage_id, r.position, r.epc, r.pilot_number, r.pilot_name, r.category, r.laps, r.total_time, r.last_lap, r.diff_first, r.diff_prev, r.best_lap, r.avg_speed, r.points); });
      stmt.finalize();
    });
    fs.unlinkSync(req.file.path); res.json({ message: "OK!", data: resultsToSave });
  } catch (error) { console.error(error); res.status(500).json({ error: "Erro." }); }
});
app.get('/api/standings/overall', (req, res) => { db.all(`SELECT pilot_name, pilot_number, category, SUM(points) as total_points FROM results GROUP BY pilot_number, category ORDER BY category ASC, total_points DESC`, [], (err, rows) => { if (err) return res.status(500).json({ error: err.message }); res.json(rows); }); });
app.get('/api/stages/:id/standings', (req, res) => { db.all(`SELECT pilot_name, pilot_number, category, points as total_points FROM results WHERE stage_id = ? ORDER BY category ASC, points DESC`, [req.params.id], (err, rows) => { if (err) return res.status(500).json({ error: err.message }); res.json(rows); }); });

app.listen(port, () => { console.log(`Server running at http://localhost:${port}`); });
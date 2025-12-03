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

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: { error: "Muitas tentativas. Bloqueado por 15 min." },
  standardHeaders: true, legacyHeaders: false,
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => { if (!fs.existsSync('uploads')) fs.mkdirSync('uploads'); cb(null, 'uploads/'); },
  filename: (req, file, cb) => { const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9); cb(null, uniqueSuffix + path.extname(file.originalname)); }
});
const fileFilter = (req, file, cb) => {
  const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.ms-excel', 'text/csv', 'application/csv'];
  if (allowed.includes(file.mimetype)) cb(null, true); else cb(new Error('Tipo inválido.'), false);
};
const upload = multer({ storage, fileFilter });

app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" })); 
app.use(bodyParser.json());

// CONFIGURAÇÃO DE CORS: CRUCIAL PARA VERCEL
// Seu Frontend e Backend estão no Vercel (diferentes subdomínios)
app.use(cors({
    origin: ['https://tamura-backend.vercel.app', 'http://localhost:5173', 'https://[SEU-FRONTEND-DOMINIO].vercel.app'], 
    credentials: true
}));

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

// FUNÇÃO HELPER: Garante que strings vazias ('') virem NULL para o Postgres DATE
const sanitize = (value) => (value === '' ? null : value);


// =====================================================
// 2. BANCO DE DADOS (POSTGRESQL)
// =====================================================

const pool = new Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT || 5432,
  ssl: process.env.PG_SSL === 'true' ? { rejectUnauthorized: false } : false
});

const query = (text, params) => pool.query(text, params);

const DEFAULT_PLANS = [
  { id: '50cc',       name: '50cc',          price: 80,  limit_cat: 1,  allowed: JSON.stringify(['50cc']), description: 'Exclusivo para categoria 50cc' },
  { id: 'fem',        name: 'Feminino',      price: 80,  limit_cat: 1,  allowed: JSON.stringify(['Feminino']), description: 'Exclusivo para categoria Feminino' },
  { id: '65cc',       name: '65cc',          price: 130, limit_cat: 1,  allowed: JSON.stringify(['65cc']), description: 'Exclusivo para categoria 65cc' },
  { id: 'p1',         name: '1 Categoria',   price: 130, limit_cat: 1,  allowed: null, description: 'Inscrição para uma única bateria' },
  { id: 'kids_combo', name: '65cc + 50cc',   price: 170, limit_cat: 2,  allowed: JSON.stringify(['50cc', '65cc']), description: 'Combo Promocional Kids' },
  { id: 'p2',         name: '2 Categorias',  price: 200, limit_cat: 2,  allowed: null, description: 'Desconto para correr duas baterias' },
  { id: 'full',       name: 'Full Pass',     price: 230, limit_cat: 99, allowed: null, description: 'Acesso total a todas as categorias' },
];

const initDb = async () => {
  try {
    console.log("Conectando ao PostgreSQL...");
    
    await query(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
    await query(`INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, ['pix_key', '']);

    await query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, 
      name TEXT, 
      email TEXT UNIQUE, 
      phone TEXT, 
      cpf TEXT UNIQUE, 
      bike_number TEXT, 
      chip_id TEXT, 
      password TEXT, 
      role TEXT DEFAULT 'user', 
      birth_date DATE,
      reset_token TEXT, 
      reset_expires TIMESTAMP
    )`);

    await query(`CREATE TABLE IF NOT EXISTS stages (
      id SERIAL PRIMARY KEY, 
      name TEXT, 
      location TEXT, 
      date TEXT, 
      image_url TEXT, 
      status TEXT DEFAULT 'upcoming', 
      batch_name TEXT DEFAULT 'Lote Inicial'
    )`);

    await query(`CREATE TABLE IF NOT EXISTS plans (
      id TEXT PRIMARY KEY, 
      name TEXT, 
      price REAL, 
      limit_cat INTEGER, 
      allowed TEXT, 
      description TEXT
    )`);

    const plansCount = await query("SELECT count(*) as count FROM plans");
    if (parseInt(plansCount.rows[0].count) === 0) {
      for (const plan of DEFAULT_PLANS) {
        await query(
          "INSERT INTO plans (id, name, price, limit_cat, allowed, description) VALUES ($1, $2, $3, $4, $5, $6)",
          [plan.id, plan.name, plan.price, plan.limit_cat, plan.allowed, plan.description]
        );
      }
    }

    await query(`CREATE TABLE IF NOT EXISTS stage_prices (
        stage_id INTEGER,
        plan_id TEXT,
        price REAL,
        PRIMARY KEY (stage_id, plan_id),
        FOREIGN KEY(stage_id) REFERENCES stages(id) ON DELETE CASCADE,
        FOREIGN KEY(plan_id) REFERENCES plans(id)
    )`);

    await query(`CREATE TABLE IF NOT EXISTS results (
      id SERIAL PRIMARY KEY, 
      stage_id INTEGER, 
      position INTEGER, 
      epc TEXT, 
      pilot_number TEXT, 
      pilot_name TEXT, 
      category TEXT, 
      laps TEXT, 
      total_time TEXT, 
      last_lap TEXT, 
      diff_first TEXT, 
      diff_prev TEXT, 
      best_lap TEXT, 
      avg_speed TEXT, 
      points INTEGER, 
      FOREIGN KEY(stage_id) REFERENCES stages(id) ON DELETE CASCADE
    )`);

    await query(`CREATE TABLE IF NOT EXISTS registrations (
      id SERIAL PRIMARY KEY, 
      user_id INTEGER, 
      stage_id INTEGER, 
      pilot_name TEXT, 
      pilot_number TEXT, 
      plan_name TEXT, 
      categories TEXT, 
      total_price REAL, 
      status TEXT DEFAULT 'pending', 
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
      FOREIGN KEY(user_id) REFERENCES users(id), 
      FOREIGN KEY(stage_id) REFERENCES stages(id) ON DELETE CASCADE
    )`);

    const adminEmail = '10tamura@gmail.com'; 
    const rawPass = '1234';
    const adminUser = await query("SELECT * FROM users WHERE email = $1", [adminEmail]);
    
    if (adminUser.rows.length === 0) {
      const hashedPassword = bcrypt.hashSync(rawPass, 10);
      await query(
        `INSERT INTO users (name, email, phone, cpf, bike_number, password, role) VALUES ($1, $2, $3, $4, $5, $6, 'admin')`,
        ['Admin Tamura', adminEmail, '999999999', '00000000000', '00', hashedPassword]
      );
      console.log("Admin padrão criado.");
    }

    console.log("Banco de dados PostgreSQL inicializado com sucesso.");
  } catch (err) {
    console.error("Erro ao inicializar banco de dados:", err);
  }
};

initDb();

const getPointsByPosition = (position) => {
  const pointsMap = { 1: 25, 2: 22, 3: 20, 4: 18, 5: 16, 6: 15, 7: 14, 8: 13, 9: 12, 10: 11, 11: 10, 12: 9, 13: 8, 14: 7, 15: 6, 16: 5, 17: 4, 18: 3, 19: 2, 20: 1 };
  return pointsMap[position] || 0;
};

// =====================================================
// ROTAS API
// =====================================================

app.get('/api/admin/backup', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Acesso negado." });
    res.status(501).json({ error: "Backup via arquivo não suportado no PostgreSQL. Utilize pg_dump." });
});

app.get('/api/settings/:key', async (req, res) => {
    try {
        const result = await query("SELECT value FROM settings WHERE key = $1", [req.params.key]);
        res.json({ value: result.rows.length > 0 ? result.rows[0].value : '' });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.put('/api/settings/:key', authenticateToken, async (req, res) => {
    try {
        await query(
            "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
            [req.params.key, req.body.value]
        );
        res.json({ message: "Atualizado!" });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.post('/register', async (req, res) => {
  const { name, email, phone, cpf, bike_number, password, birth_date } = req.body;
  
  if (!name || !email || !cpf || !password || !birth_date) {
      return res.status(400).json({ error: "Todos os campos obrigatórios (incluindo Data de Nascimento) devem ser preenchidos." });
  }

  try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const result = await query(
        `INSERT INTO users (name, email, phone, cpf, bike_number, password, role, birth_date) 
         VALUES ($1, $2, $3, $4, $5, $6, 'user', $7) RETURNING id`, 
        [name, email, phone, cpf, bike_number, hashedPassword, sanitize(birth_date)]
      );
      res.json({ message: "Sucesso!", userId: result.rows[0].id });
  } catch (err) {
      if (err.code === '23505') {
          return res.status(400).json({ error: "Email ou CPF já cadastrado." });
      }
      res.status(500).json({ error: err.message });
  }
});

app.post('/login', loginLimiter, async (req, res) => {
  const { identifier, password } = req.body;
  try {
      const result = await query(`SELECT * FROM users WHERE (email = $1 OR name = $1 OR phone = $1)`, [identifier]);
      const user = result.rows[0];
      
      if (!user) return res.status(401).json({ error: "Não encontrado." });
      
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: "Senha incorreta." });
      
      const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
      res.json({ id: user.id, name: user.name, role: user.role, bike_number: user.bike_number, token });
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const result = await query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ error: "E-mail não encontrado." });
        
        const token = crypto.randomBytes(20).toString('hex');
        const now = new Date(); now.setHours(now.getHours() + 1);
        
        await query("UPDATE users SET reset_token = $1, reset_expires = $2 WHERE id = $3", [token, now, user.id]);
        await sendEmail(email, "Recuperação - Tamura Eventos", `Seu código de recuperação é: ${token}`);
        res.json({ message: "Token enviado." });
    } catch (err) { 
        res.status(500).json({ error: "Erro interno" }); 
    }
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    try {
        const result = await query("SELECT * FROM users WHERE reset_token = $1 AND reset_expires > NOW()", [token]);
        const user = result.rows[0];
        
        if (!user) return res.status(400).json({ error: "Token inválido/expirado." });
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await query("UPDATE users SET password = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2", [hashedPassword, user.id]);
        res.json({ message: "Senha alterada!" });
    } catch (err) { 
        res.status(500).json({ error: "Erro ao salvar." }); 
    }
});

app.get('/api/plans', async (req, res) => {
  try {
      const result = await query("SELECT * FROM plans");
      res.json(result.rows.map(r => ({ ...r, allowed: r.allowed ? JSON.parse(r.allowed) : null })));
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  }
});

app.get('/api/users', authenticateToken, async (req, res) => {
  try {
      const result = await query(`SELECT id, name, email, phone, cpf, bike_number, chip_id, role, birth_date FROM users ORDER BY name ASC`);
      res.json(result.rows);
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  }
});

app.get('/api/users/:id', authenticateToken, async (req, res) => {
    if (req.user.id != req.params.id && req.user.role !== 'admin') return res.status(403).json({ error: "Acesso negado." });
    try {
        const result = await query("SELECT id, name, email, phone, cpf, bike_number, chip_id, role, birth_date FROM users WHERE id = $1", [req.params.id]);
        res.json(result.rows[0] || {});
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const { name, email, phone, bike_number, chip_id, role, birth_date } = req.body;
    try {
        await query(
            `UPDATE users SET name = $1, email = $2, phone = $3, bike_number = $4, chip_id = $5, role = $6, birth_date = $7 WHERE id = $8`, 
            [name, email, phone, bike_number, chip_id, role, sanitize(birth_date), req.params.id]
        );
        res.json({ message: "Atualizado!" });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        await query("DELETE FROM users WHERE id = $1", [req.params.id]);
        res.json({ message: "Excluído." });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.get('/api/stages', async (req, res) => {
  try {
      const result = await query("SELECT * FROM stages ORDER BY date ASC");
      res.json(result.rows);
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  }
});

app.post('/api/stages', authenticateToken, upload.single('image'), async (req, res) => {
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
  const client = await pool.connect();
  try {
      await client.query('BEGIN');
      const insertRes = await client.query(
          `INSERT INTO stages (name, location, date, image_url, batch_name) VALUES ($1, $2, $3, $4, 'Lote Inicial') RETURNING id`, 
          [req.body.name, req.body.location, req.body.date, imageUrl]
      );
      const newStageId = insertRes.rows[0].id;

      for (const p of DEFAULT_PLANS) {
          await client.query("INSERT INTO stage_prices (stage_id, plan_id, price) VALUES ($1, $2, $3)", [newStageId, p.id, p.price]);
      }
      
      await client.query('COMMIT');
      res.json({ id: newStageId, message: "Criado!" });
  } catch (err) {
      await client.query('ROLLBACK');
      res.status(500).json({ error: err.message });
  } finally {
      client.release();
  }
});

app.put('/api/stages/:id', authenticateToken, upload.single('image'), async (req, res) => {
    let queryText = `UPDATE stages SET name = $1, location = $2, date = $3 WHERE id = $4`;
    let params = [req.body.name, req.body.location, req.body.date, req.params.id];
    
    if (req.file) { 
        queryText = `UPDATE stages SET name = $1, location = $2, date = $3, image_url = $4 WHERE id = $5`;
        params = [req.body.name, req.body.location, req.body.date, `/uploads/${req.file.filename}`, req.params.id];
    }
    
    try {
        await query(queryText, params);
        res.json({ message: "Atualizado!" });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.delete('/api/stages/:id', authenticateToken, async (req, res) => {
    try {
        const imgRes = await query("SELECT image_url FROM stages WHERE id = $1", [req.params.id]);
        if (imgRes.rows[0] && imgRes.rows[0].image_url) {
            const filePath = path.join(__dirname, imgRes.rows[0].image_url);
            fs.unlink(filePath, (err) => {});
        }
        await query("DELETE FROM stages WHERE id = $1", [req.params.id]);
        res.json({ message: "Excluído." });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.get('/api/stages/:id/prices', async (req, res) => {
    const stageId = req.params.id;
    const sql = `
        SELECT p.id, p.name, p.limit_cat, p.allowed, p.description, 
               COALESCE(sp.price, p.price) as price 
        FROM plans p
        LEFT JOIN stage_prices sp ON p.id = sp.plan_id AND sp.stage_id = $1
    `;
    try {
        const plansRes = await query(sql, [stageId]);
        const stageRes = await query("SELECT batch_name FROM stages WHERE id = $1", [stageId]);
        
        const batchName = stageRes.rows[0] ? stageRes.rows[0].batch_name : 'Lote Inicial';
        const formattedPlans = plansRes.rows.map(r => ({ ...r, allowed: r.allowed ? JSON.parse(r.allowed) : null }));
        
        res.json({ batch_name: batchName, plans: formattedPlans });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.put('/api/stages/:id/prices', authenticateToken, async (req, res) => {
    const stageId = req.params.id;
    const { batch_name, plans } = req.body;
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        await client.query("UPDATE stages SET batch_name = $1 WHERE id = $2", [batch_name, stageId]);
        
        for (const p of plans) {
            await client.query(
                `INSERT INTO stage_prices (stage_id, plan_id, price) VALUES ($1, $2, $3)
                 ON CONFLICT (stage_id, plan_id) DO UPDATE SET price = $3`,
                [stageId, p.id, p.price]
            );
        }
        await client.query('COMMIT');
        res.json({ message: "Preços atualizados!" });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: "Erro lote" });
    } finally {
        client.release();
    }
});

app.post('/api/registrations', authenticateToken, async (req, res) => {
  const { user_id, stage_id, pilot_name, pilot_number, plan_name, categories, total_price } = req.body;
  const categoriesStr = Array.isArray(categories) ? categories.join(', ') : categories;
  try {
      const result = await query(
          `INSERT INTO registrations (user_id, stage_id, pilot_name, pilot_number, plan_name, categories, total_price) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, 
          [user_id, stage_id, pilot_name, pilot_number, plan_name, categoriesStr, total_price]
      );
      res.json({ message: "Inscrição OK!", registrationId: result.rows[0].id });
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  }
});

app.get('/api/registrations/user/:userId', authenticateToken, async (req, res) => {
    if (req.user.id != req.params.userId && req.user.role !== 'admin') return res.status(403).json({ error: "Acesso negado." });
    try {
        const result = await query(
            `SELECT r.*, s.name as stage_name, s.date as stage_date, s.image_url FROM registrations r JOIN stages s ON r.stage_id = s.id WHERE r.user_id = $1 ORDER BY r.created_at DESC`, 
            [req.params.userId]
        );
        res.json(result.rows);
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.get('/api/registrations/stage/:stageId', authenticateToken, async (req, res) => {
    try {
        const result = await query(
            `SELECT r.*, u.phone, u.cpf, u.email FROM registrations r LEFT JOIN users u ON r.user_id = u.id WHERE r.stage_id = $1 ORDER BY r.pilot_name ASC`, 
            [req.params.stageId]
        );
        res.json(result.rows);
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.put('/api/registrations/:id/status', authenticateToken, async (req, res) => {
    const { status } = req.body;
    try {
        await query(`UPDATE registrations SET status = $1 WHERE id = $2`, [status, req.params.id]);
        
        if (status === 'paid') {
            const regRes = await query(
                `SELECT r.*, u.email, s.name as stage_name FROM registrations r JOIN users u ON r.user_id = u.id JOIN stages s ON r.stage_id = s.id WHERE r.id = $1`, 
                [req.params.id]
            );
            const row = regRes.rows[0];
            if (row && row.email) {
                await sendEmail(
                    row.email, 
                    "Inscrição Confirmada - Tamura Eventos", 
                    `Olá ${row.pilot_name},\n\nSua inscrição para a etapa "${row.stage_name}" foi CONFIRMADA!\n\nPrepare sua moto e boa prova!\nEquipe Tamura Eventos`
                );
            }
        }
        res.json({ message: "Status atualizado!" });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.get('/api/stages/:id/categories-status', async (req, res) => { 
    try {
        const result = await query(`SELECT DISTINCT category FROM results WHERE stage_id = $1`, [req.params.id]);
        res.json(result.rows.map(r => r.category));
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.get('/api/stages/:id/results/:category', async (req, res) => { 
    try {
        const result = await query(
            `SELECT * FROM results WHERE stage_id = $1 AND category = $2 ORDER BY position ASC`, 
            [req.params.id, req.params.category]
        );
        res.json(result.rows);
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.post('/api/stages/:id/upload/:category', authenticateToken, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Sem arquivo." });
  const client = await pool.connect();
  
  try {
    const workbook = xlsx.readFile(req.file.path);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const data = xlsx.utils.sheet_to_json(sheet, { header: 1, defval: "" });
    
    const resultsToSave = [];
    let headerFound = false;
    
    data.forEach((row) => {
      if (!headerFound) { 
          if (row[0] && (row[0].toString().trim() === 'P' || row[0].toString().trim() === 'Pos')) headerFound = true; 
          return; 
      }
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

    await client.query('BEGIN');
    await client.query(`DELETE FROM results WHERE stage_id = $1 AND category = $2`, [req.params.id, req.params.category]);
    
    for (const r of resultsToSave) {
        await client.query(
            `INSERT INTO results (stage_id, position, epc, pilot_number, pilot_name, category, laps, total_time, last_lap, diff_first, diff_prev, best_lap, avg_speed, points) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
            [r.stage_id, r.position, r.epc, r.pilot_number, r.pilot_name, r.category, r.laps, r.total_time, r.last_lap, r.diff_first, r.diff_prev, r.best_lap, r.avg_speed, r.points]
        );
    }
    await client.query('COMMIT');
    
    fs.unlinkSync(req.file.path); 
    res.json({ message: "OK!", data: resultsToSave });
  } catch (error) { 
      await client.query('ROLLBACK');
      console.error(error); 
      res.status(500).json({ error: "Erro no processamento." }); 
  } finally {
      client.release();
  }
});

app.get('/api/standings/overall', async (req, res) => { 
    try {
        const result = await query(
            `SELECT pilot_name, pilot_number, category, SUM(points) as total_points FROM results GROUP BY pilot_number, pilot_name, category ORDER BY category ASC, total_points DESC`
        );
        res.json(result.rows);
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.get('/api/stages/:id/standings', async (req, res) => { 
    try {
        const result = await query(
            `SELECT * FROM results WHERE stage_id = $1 ORDER BY category ASC, position ASC`, 
            [req.params.id]
        );
        res.json(result.rows); 
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

// EXPORTAÇÃO PARA O VERCEL SERVERLESS (substitui app.listen)
module.exports = app;
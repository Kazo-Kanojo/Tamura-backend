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

// --- IMPORTAÇÕES PARA O CLOUDINARY ---
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
const port = process.env.PORT || 3000;

// =====================================================
// 1. CONFIGURAÇÕES
// =====================================================

// Helper de DNS para evitar erros de envio de email em ambientes serverless
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

// Configuração de CORS - Adicione o domínio do seu frontend aqui
app.use(cors({
    origin: ['https://tamura-frontend.vercel.app', 'http://localhost:5173'], // Atualize com seu domínio frontend real
    credentials: true
}));

app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" })); 
app.use(bodyParser.json());

// --- CONFIGURAÇÃO DO CLOUDINARY ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// --- 1. CONFIGURAÇÃO DE UPLOAD PARA IMAGENS (CLOUDINARY) ---
const storageImages = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'tamura-eventos', // Nome da pasta no Cloudinary
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
  },
});
const uploadImage = multer({ storage: storageImages });

// --- 2. CONFIGURAÇÃO DE UPLOAD PARA ARQUIVOS DE DADOS/EXCEL (MEMÓRIA) ---
// Usamos memória para poder ler o buffer do Excel imediatamente sem salvar em disco/nuvem
const storageFiles = multer.memoryStorage();
const uploadFile = multer({ storage: storageFiles });


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

// Helper para converter string vazia em NULL (Postgres requer isso para datas)
const sanitize = (value) => (value === '' ? null : value);

// =====================================================
// 2. BANCO DE DADOS (CONEXÃO POSTGRESQL)
// =====================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || `postgresql://${process.env.PG_USER}:${process.env.PG_PASSWORD}@${process.env.PG_HOST}:${process.env.PG_PORT}/${process.env.PG_DATABASE}?sslmode=require`,
  ssl: { rejectUnauthorized: false } // Necessário para Neon/Render
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

// Inicialização das Tabelas
const initDb = async () => {
  try {
    // Configurações
    await query(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
    await query(`INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, ['pix_key', '']);

    // Usuários
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

    // Etapas
    await query(`CREATE TABLE IF NOT EXISTS stages (
      id SERIAL PRIMARY KEY, 
      name TEXT, 
      location TEXT, 
      date TEXT, 
      image_url TEXT, 
      status TEXT DEFAULT 'upcoming', 
      batch_name TEXT DEFAULT 'Lote Inicial'
    )`);

    // Planos
    await query(`CREATE TABLE IF NOT EXISTS plans (
      id TEXT PRIMARY KEY, 
      name TEXT, 
      price REAL, 
      limit_cat INTEGER, 
      allowed TEXT, 
      description TEXT
    )`);

    // Insere planos padrão se não existirem
    const plansCount = await query("SELECT count(*) as count FROM plans");
    if (parseInt(plansCount.rows[0].count) === 0) {
      for (const plan of DEFAULT_PLANS) {
        await query(
          "INSERT INTO plans (id, name, price, limit_cat, allowed, description) VALUES ($1, $2, $3, $4, $5, $6)",
          [plan.id, plan.name, plan.price, plan.limit_cat, plan.allowed, plan.description]
        );
      }
    }

    // Preços por Etapa
    await query(`CREATE TABLE IF NOT EXISTS stage_prices (
        stage_id INTEGER,
        plan_id TEXT,
        price REAL,
        PRIMARY KEY (stage_id, plan_id),
        FOREIGN KEY(stage_id) REFERENCES stages(id) ON DELETE CASCADE,
        FOREIGN KEY(plan_id) REFERENCES plans(id)
    )`);

    // Resultados
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

    // Inscrições
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

    // Admin Padrão
    const adminEmail = '10tamura@gmail.com'; 
    const adminUser = await query("SELECT * FROM users WHERE email = $1", [adminEmail]);
    
    if (adminUser.rows.length === 0) {
      const hashedPassword = bcrypt.hashSync('1234', 10);
      await query(
        `INSERT INTO users (name, email, phone, cpf, bike_number, password, role) VALUES ($1, $2, $3, $4, $5, $6, 'admin')`,
        ['Admin Tamura', adminEmail, '999999999', '00000000000', '00', hashedPassword]
      );
      console.log("Admin padrão criado.");
    }
  } catch (err) {
    console.error("Erro ao inicializar DB:", err);
  }
};

// Executa a inicialização ao iniciar
initDb();

const getPointsByPosition = (position) => {
  const pointsMap = { 1: 25, 2: 22, 3: 20, 4: 18, 5: 16, 6: 15, 7: 14, 8: 13, 9: 12, 10: 11, 11: 10, 12: 9, 13: 8, 14: 7, 15: 6, 16: 5, 17: 4, 18: 3, 19: 2, 20: 1 };
  return pointsMap[position] || 0;
};

// =====================================================
// ROTAS API
// =====================================================

app.get('/', (req, res) => {
    res.send('Tamura API Running with PostgreSQL');
});

// Configurações
app.get('/api/settings/:key', async (req, res) => {
    try {
        const result = await query("SELECT value FROM settings WHERE key = $1", [req.params.key]);
        res.json({ value: result.rows.length > 0 ? result.rows[0].value : '' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/settings/:key', authenticateToken, async (req, res) => {
    try {
        await query("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2", [req.params.key, req.body.value]);
        res.json({ message: "Atualizado!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Auth
app.post('/register', async (req, res) => {
  const { name, email, phone, cpf, bike_number, password, birth_date } = req.body;
  if (!name || !email || !cpf || !password) return res.status(400).json({ error: "Campos obrigatórios faltando." });

  try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const result = await query(
        `INSERT INTO users (name, email, phone, cpf, bike_number, password, role, birth_date) 
         VALUES ($1, $2, $3, $4, $5, $6, 'user', $7) RETURNING id`, 
        [name, email, phone, cpf, bike_number, hashedPassword, sanitize(birth_date)]
      );
      res.json({ message: "Sucesso!", userId: result.rows[0].id });
  } catch (err) {
      if (err.code === '23505') return res.status(400).json({ error: "Email ou CPF já cadastrado." });
      res.status(500).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { identifier, password } = req.body;
  try {
      const result = await query(`SELECT * FROM users WHERE (email = $1 OR name = $1 OR phone = $1)`, [identifier]);
      const user = result.rows[0];
      
      if (!user) return res.status(401).json({ error: "Não encontrado." });
      
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: "Senha incorreta." });
      
      const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
      res.json({ id: user.id, name: user.name, role: user.role, bike_number: user.bike_number, token });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
// --- RECUPERAÇÃO DE SENHA ---

// 1. Solicitar Recuperação (Envia Email com Token)
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email é obrigatório." });

  try {
    const userResult = await query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];

    if (!user) {
      // Por segurança, não dizemos se o email existe ou não, mas aqui retornamos erro para facilitar
      return res.status(404).json({ error: "Email não encontrado." });
    }

    // Gera um token simples e data de expiração (1 hora)
    const token = crypto.randomBytes(8).toString('hex');
    const now = new Date();
    now.setHours(now.getHours() + 1);

    await query(
      "UPDATE users SET reset_token = $1, reset_expires = $2 WHERE id = $3",
      [token, now, user.id]
    );

    // Envia o email
    const mailOptions = {
      to: user.email,
      subject: 'Recuperação de Senha - Tamura Eventos',
      text: `Você solicitou a recuperação de senha.\n\nUse o seguinte token para redefinir sua senha: ${token}\n\nSe você não solicitou isso, ignore este email.`
    };

    await sendEmail(mailOptions.to, mailOptions.subject, mailOptions.text);

    res.json({ message: "Email enviado com sucesso!" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao processar solicitação." });
  }
});

// 2. Redefinir a Senha (Usa o Token)
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: "Token e nova senha são obrigatórios." });

  try {
    // Busca usuário com token válido e que não tenha expirado
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

    // Atualiza a senha e limpa o token
    await query(
      "UPDATE users SET password = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2",
      [hashedPassword, user.id]
    );

    res.json({ message: "Senha alterada com sucesso!" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao redefinir senha." });
  }
});
// Etapas
app.get('/api/stages', async (req, res) => {
  try {
      const result = await query("SELECT * FROM stages ORDER BY date ASC");
      res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- ROTA POST DE STAGES (Usa uploadImage) ---
app.post('/api/stages', authenticateToken, uploadImage.single('image'), async (req, res) => {
  const imageUrl = req.file ? req.file.path : null;
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
      console.error(err);
      res.status(500).json({ error: err.message });
  } finally {
      client.release();
  }
});

// --- ROTA PUT DE STAGES (Usa uploadImage) ---
app.put('/api/stages/:id', authenticateToken, uploadImage.single('image'), async (req, res) => {
    let queryText = `UPDATE stages SET name = $1, location = $2, date = $3 WHERE id = $4`;
    let params = [req.body.name, req.body.location, req.body.date, req.params.id];
    
    if (req.file) { 
        queryText = `UPDATE stages SET name = $1, location = $2, date = $3, image_url = $4 WHERE id = $5`;
        params = [req.body.name, req.body.location, req.body.date, req.file.path, req.params.id];
    }
    
    try {
        await query(queryText, params);
        res.json({ message: "Atualizado!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/stages/:id', authenticateToken, async (req, res) => {
    try {
        await query("DELETE FROM stages WHERE id = $1", [req.params.id]);
        res.json({ message: "Excluído." });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Users
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
      const result = await query(`SELECT id, name, email, phone, cpf, bike_number, chip_id, role, birth_date FROM users ORDER BY name ASC`);
      res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const { name, email, phone, bike_number, chip_id, role, birth_date } = req.body;
    try {
        await query(
            `UPDATE users SET name = $1, email = $2, phone = $3, bike_number = $4, chip_id = $5, role = $6, birth_date = $7 WHERE id = $8`, 
            [name, email, phone, bike_number, chip_id, role, sanitize(birth_date), req.params.id]
        );
        res.json({ message: "Atualizado!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        await query("DELETE FROM users WHERE id = $1", [req.params.id]);
        res.json({ message: "Excluído." });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Preços por Etapa
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
    } catch (err) { res.status(500).json({ error: err.message }); }
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

// Inscrições
app.get('/api/registrations/stage/:stageId', authenticateToken, async (req, res) => {
    try {
        const result = await query(
            `SELECT r.*, u.phone, u.cpf, u.email FROM registrations r LEFT JOIN users u ON r.user_id = u.id WHERE r.stage_id = $1 ORDER BY r.pilot_name ASC`, 
            [req.params.stageId]
        );
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/stages/:id/categories-status', async (req, res) => { 
    try {
        const result = await query(`SELECT DISTINCT category FROM results WHERE stage_id = $1`, [req.params.id]);
        res.json(result.rows.map(r => r.category));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// RESULTADOS (ADMIN)
app.get('/api/stages/:id/results/:category', async (req, res) => { 
    try {
        const result = await query(
            `SELECT * FROM results WHERE stage_id = $1 AND category = $2 ORDER BY position ASC`, 
            [req.params.id, req.params.category]
        );
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- ROTA DE UPLOAD EXCEL (CORRIGIDA: Usa uploadFile e lê da memória) ---
app.post('/api/stages/:id/upload/:category', authenticateToken, uploadFile.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Sem arquivo." });
  const client = await pool.connect();
  
  try {
    // Lê o arquivo Excel diretamente do buffer da memória
    const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });

    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const data = xlsx.utils.sheet_to_json(sheet, { header: 1, defval: "" });
    
    const resultsToSave = [];
    let headerFound = false;
    
    data.forEach((row) => {
      // Procura a linha de cabeçalho (começa com 'P' ou 'Pos')
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
    
    res.json({ message: "OK!", data: resultsToSave });
  } catch (error) { 
      await client.query('ROLLBACK');
      console.error(error); 
      res.status(500).json({ error: "Erro no processamento." }); 
  } finally {
      client.release();
  }
});

// --- NOVAS ROTAS PARA TABELA DE PONTUAÇÃO (CORREÇÃO ERRO 2) ---

// 1. Classificação Geral do Campeonato (Soma de todas as etapas)
app.get('/api/standings/overall', async (req, res) => {
    try {
        const result = await query(
            `SELECT pilot_name, pilot_number, category, SUM(points) as total_points 
             FROM results 
             GROUP BY pilot_name, pilot_number, category 
             ORDER BY category ASC, total_points DESC`
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. Classificação de uma Etapa Específica
app.get('/api/stages/:id/standings', async (req, res) => {
    try {
        const result = await query(
            `SELECT position, pilot_name, pilot_number, points, category, laps, total_time, diff_first, best_lap 
             FROM results 
             WHERE stage_id = $1 
             ORDER BY category ASC, position ASC`, 
            [req.params.id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Importante: Exporta o app para o Vercel Serverless Function
module.exports = app;
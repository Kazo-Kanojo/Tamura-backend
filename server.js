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
const allowedOrigins = [
    'https://tamura.esp.br', 
    'https://www.tamura.esp.br',
    'http://localhost:5173'
];

app.use(cors({
    origin: function (origin, callback) {
        // Permite requisições sem origin (como ferramentas de teste ou mobile)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            // Log para você saber qual domínio está sendo bloqueado se o erro persistir
            console.log("Domínio bloqueado pelo CORS:", origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
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

const sanitize = (value) => (value === '' ? null : value);

// =====================================================
// 2. BANCO DE DADOS (CONEXÃO POSTGRESQL)
// =====================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 1, 
  idleTimeoutMillis: 30000,
  // Aumente o timeout para 10 ou 15 segundos para dar tempo do banco acordar
  connectionTimeoutMillis: 15000, 
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

const DEFAULT_CATEGORIES = [
  "50cc", "65cc", "Feminino", "Free Force One", "Importada Amador","Junior", 
  "Nacional Amador", "Open Importada", "Open Nacional", "Over 250", 
  "Ultimate 250x230", "VX 250f Nacional", "VX230","VX1","VX2", 
  "VX3 Importada", "VX3 Nacional", "VX4", "VX5", "VX6", "VX7",
  "Taça importada","Taça nacional", "trilheiros"
];

// Inicialização das Tabelas
// const initDb = async () => {
//   try {
//     await query(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
//     await query(`INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, ['pix_key', '']);

//     await query(`CREATE TABLE IF NOT EXISTS users (
//       id SERIAL PRIMARY KEY, 
//       name TEXT, 
//       email TEXT UNIQUE, 
//       phone TEXT, 
//       cpf TEXT UNIQUE, 
//       rg TEXT,
//       medical_insurance TEXT,
//       team TEXT,
//       emergency_phone TEXT,
//       bike_number TEXT, 
//       chip_id TEXT, 
//       password TEXT, 
//       role TEXT DEFAULT 'user', 
//       birth_date DATE,
//       reset_token TEXT, 
//       reset_expires TIMESTAMP
//     )`);

//     await query(`CREATE TABLE IF NOT EXISTS stages (
//       id SERIAL PRIMARY KEY, 
//       name TEXT, 
//       location TEXT, 
//       date TEXT, 
//       end_date TEXT, 
//       image_url TEXT, 
//       status TEXT DEFAULT 'upcoming', 
//       batch_name TEXT DEFAULT 'Lote Inicial'
//     )`);

//     await query(`CREATE TABLE IF NOT EXISTS plans (
//       id TEXT PRIMARY KEY, 
//       name TEXT, 
//       price REAL, 
//       limit_cat INTEGER, 
//       allowed TEXT, 
//       description TEXT
//     )`);

//     const plansCount = await query("SELECT count(*) as count FROM plans");
//     if (parseInt(plansCount.rows[0].count) === 0) {
//       for (const plan of DEFAULT_PLANS) {
//         await query(
//           "INSERT INTO plans (id, name, price, limit_cat, allowed, description) VALUES ($1, $2, $3, $4, $5, $6)",
//           [plan.id, plan.name, plan.price, plan.limit_cat, plan.allowed, plan.description]
//         );
//       }
//     }

//     // --- NOVA TABELA DE CATEGORIAS ---
//     await query(`CREATE TABLE IF NOT EXISTS categories (
//       id SERIAL PRIMARY KEY, 
//       name TEXT UNIQUE NOT NULL
//     )`);

//     const catCount = await query("SELECT count(*) as count FROM categories");
//     if (parseInt(catCount.rows[0].count) === 0) {
//       for (const cat of DEFAULT_CATEGORIES) {
//         await query(
//           "INSERT INTO categories (name) VALUES ($1) ON CONFLICT (name) DO NOTHING",
//           [cat]
//         );
//       }
//       console.log("Categorias padrão inseridas.");
//     }

//     await query(`CREATE TABLE IF NOT EXISTS stage_prices (
//         stage_id INTEGER,
//         plan_id TEXT,
//         price REAL,
//         PRIMARY KEY (stage_id, plan_id),
//         FOREIGN KEY(stage_id) REFERENCES stages(id) ON DELETE CASCADE,
//         FOREIGN KEY(plan_id) REFERENCES plans(id)
//     )`);

//     await query(`CREATE TABLE IF NOT EXISTS results (
//       id SERIAL PRIMARY KEY, 
//       stage_id INTEGER, 
//       position INTEGER, 
//       epc TEXT, 
//       pilot_number TEXT, 
//       pilot_name TEXT, 
//       category TEXT, 
//       laps TEXT, 
//       total_time TEXT, 
//       last_lap TEXT, 
//       diff_first TEXT, 
//       diff_prev TEXT, 
//       best_lap TEXT, 
//       avg_speed TEXT, 
//       points INTEGER, 
//       FOREIGN KEY(stage_id) REFERENCES stages(id) ON DELETE CASCADE
//     )`);

//     await query(`CREATE TABLE IF NOT EXISTS registrations (
//       id SERIAL PRIMARY KEY, 
//       user_id INTEGER, 
//       stage_id INTEGER, 
//       pilot_name TEXT, 
//       pilot_number TEXT, 
//       plan_name TEXT, 
//       categories TEXT, 
//       total_price REAL, 
//       status TEXT DEFAULT 'pending', 
//       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
//       FOREIGN KEY(user_id) REFERENCES users(id), 
//       FOREIGN KEY(stage_id) REFERENCES stages(id) ON DELETE CASCADE
//     )`);

//     const adminEmail = '10tamura@gmail.com'; 
//     const adminUser = await query("SELECT * FROM users WHERE email = $1", [adminEmail]);
    
//     if (adminUser.rows.length === 0) {
//       const hashedPassword = bcrypt.hashSync('1234', 10);
//       await query(
//         `INSERT INTO users (name, email, phone, cpf, bike_number, password, role) VALUES ($1, $2, $3, $4, $5, $6, 'admin')`,
//         ['Admin Tamura', adminEmail, '999999999', '00000000000', '00', hashedPassword]
//       );
//       console.log("Admin padrão criado.");
//     }
//   } catch (err) {
//     console.error("Erro ao inicializar DB:", err);
//   }
// };

// initDb();

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
  // Recebe do Frontend em CamelCase (padrão JS)
  const { 
    name, email, phone, cpf, rg, medical_insurance, 
    team, emergency_phone, address, bike_number, password, birth_date, 
    modeloMoto // <--- Sua variável aqui
  } = req.body;

  if (!name || !email || !cpf || !password) {
    return res.status(400).json({ error: "Nome, Email, CPF e Senha são obrigatórios." });
  }

  try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const result = await query(
        // SQL: AQUI PRECISA SER modelo_moto (Snake Case) PARA O BANCO ACEITAR
        `INSERT INTO users (
          name, email, phone, cpf, rg, medical_insurance, 
          team, emergency_phone, address, bike_number, password, role, birth_date, 
          modelo_moto 
         ) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'user', $12, $13) RETURNING id`, 
        [
          name, 
          email, 
          phone, 
          cpf, 
          sanitize(rg), 
          sanitize(medical_insurance), 
          sanitize(team), 
          sanitize(emergency_phone), 
          sanitize(address), 
          bike_number, 
          hashedPassword, 
          sanitize(birth_date),
          sanitize(modeloMoto) // <--- Aqui vai a variável CamelCase
        ]
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
      res.json({ id: user.id, name: user.name, role: user.role, bike_number: user.bike_number, chip_id: user.chip_id, token });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email é obrigatório." });

  try {
    const userResult = await query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];

    if (!user) {
      return res.status(404).json({ error: "Email não encontrado." });
    }

    const token = crypto.randomBytes(2).toString('hex');
    const now = new Date();
    now.setHours(now.getHours() + 1);

    await query(
      "UPDATE users SET reset_token = $1, reset_expires = $2 WHERE id = $3",
      [token, now, user.id]
    );

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

app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: "Token e nova senha são obrigatórios." });

  try {
    const result = await query(
      "SELECT * FROM users WHERE reset_token = $1 AND reset_expires > NOW()",
      [token]
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: "Token inválido ou expirado." });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

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

app.post('/api/stages', authenticateToken, uploadImage.single('image'), async (req, res) => {
  const imageUrl = req.file ? req.file.path : null;
  const client = await pool.connect();
  try {
      await client.query('BEGIN');
      const insertRes = await client.query(
          `INSERT INTO stages (name, location, date, end_date, image_url, batch_name) VALUES ($1, $2, $3, $4, $5, 'Lote Inicial') RETURNING id`, 
          [req.body.name, req.body.location, req.body.date, req.body.end_date, imageUrl]
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

app.put('/api/stages/:id', authenticateToken, uploadImage.single('image'), async (req, res) => {
    let queryText = `UPDATE stages SET name = $1, location = $2, date = $3, end_date = $4 WHERE id = $5`;
    let params = [req.body.name, req.body.location, req.body.date, req.body.end_date, req.params.id];
    
    if (req.file) { 
        queryText = `UPDATE stages SET name = $1, location = $2, date = $3, end_date = $4, image_url = $5 WHERE id = $6`;
        params = [req.body.name, req.body.location, req.body.date, req.body.end_date, req.file.path, req.params.id];
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
      // Adicionamos: rg, medical_insurance, team, emergency_phone, address
      const result = await query(`SELECT id, name, email, phone, cpf, rg, medical_insurance, team, emergency_phone, address, bike_number, chip_id, role, birth_date FROM users ORDER BY name ASC`);
      res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/me', authenticateToken, async (req, res) => {
  try {
      const result = await query(
          `SELECT id, name, email, phone, cpf, bike_number, chip_id, role, birth_date FROM users WHERE id = $1`, 
          [req.user.id] 
      );
      if (result.rows.length === 0) return res.status(404).json({ error: "Usuário não encontrado." });
      res.json(result.rows[0]);
  } catch (err) { 
      res.status(500).json({ error: err.message }); 
  }
});

// Rota SEGURA para buscar um utilizador específico
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const { 
        name, email, phone, rg, medical_insurance, 
        team, emergency_phone, address, bike_number, 
        chip_id, role, birth_date, 
        modeloMoto // <--- Variável CamelCase vinda do React
    } = req.body;
    
    // Segurança para não deixar user virar admin
    if (req.user.role !== 'admin' && role === 'admin' && req.user.role !== role) {
         return res.status(403).json({ error: "Operação não permitida." });
    }

    try {
        await query(
            // SQL: Novamente, no banco chamamos de modelo_moto
            `UPDATE users SET 
                name = $1, email = $2, phone = $3, rg = $4, medical_insurance = $5, 
                team = $6, emergency_phone = $7, address = $8, bike_number = $9, 
                chip_id = $10, role = $11, birth_date = $12, 
                modelo_moto = $13 
             WHERE id = $14`, 
            [
                name, 
                email, 
                phone, 
                sanitize(rg), 
                sanitize(medical_insurance), 
                sanitize(team), 
                sanitize(emergency_phone), 
                sanitize(address), 
                bike_number, 
                chip_id, 
                role, 
                sanitize(birth_date), 
                sanitize(modeloMoto), // <--- Valor CamelCase
                req.params.id
            ]
        );
        res.json({ message: "Atualizado!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Rota para ATUALIZAR usuário (Admin ou Próprio) ---
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const { 
        name, email, phone, rg, medical_insurance, 
        team, emergency_phone, address, bike_number, 
        chip_id, role, birth_date, modeloMoto
    } = req.body;
    
    // Trava de segurança para Roles: Impede que um usuário comum vire admin sozinho
    if (req.user.role !== 'admin' && role === 'admin' && req.user.role !== role) {
         return res.status(403).json({ error: "Operação não permitida." });
    }

    try {
        await query(
            `UPDATE users SET 
                name = $1, email = $2, phone = $3, rg = $4, medical_insurance = $5, 
                team = $6, emergency_phone = $7, address = $8, bike_number = $9, 
                chip_id = $10, role = $11, birth_date = $12, modelo_moto = $13
             WHERE id = $14`, 
            [
                name, email, phone, sanitize(rg), sanitize(medical_insurance), 
                sanitize(team), sanitize(emergency_phone), sanitize(address), 
                bike_number, chip_id, role, sanitize(birth_date), sanitize(modeloMoto), 
                req.params.id
            ]
        );
        res.json({ message: "Atualizado!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
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

// --- ROTA DE CRIAR INSCRIÇÃO (COM TRAVA DE SEGURANÇA) ---
app.post('/api/registrations', authenticateToken, async (req, res) => {
  const { user_id, stage_id, pilot_name, pilot_number, plan_name, categories, total_price } = req.body;
  const categoriesStr = Array.isArray(categories) ? categories.join(', ') : categories;

  try {
      const stageRes = await query("SELECT date, end_date FROM stages WHERE id = $1", [stage_id]);
      const stage = stageRes.rows[0];

      if (stage) {
          const eventEndDate = stage.end_date ? new Date(stage.end_date) : new Date(stage.date);
          eventEndDate.setDate(eventEndDate.getDate() + 1);
          eventEndDate.setHours(23, 59, 59, 999);
          
          const now = new Date();

          if (now > eventEndDate) {
              return res.status(400).json({ error: "As inscrições para este evento já foram encerradas." });
          }
      }

      const result = await query(
          `INSERT INTO registrations (user_id, stage_id, pilot_name, pilot_number, plan_name, categories, total_price) 
           VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
          [user_id, stage_id, pilot_name, pilot_number, plan_name, categoriesStr, total_price]
      );
      res.json({ message: "Inscrição realizada com sucesso!", id: result.rows[0].id });
  } catch (err) {
      console.error("Erro ao salvar inscrição:", err);
      res.status(500).json({ error: "Erro ao processar inscrição." });
  }
});

app.put('/api/registrations/:id/status', authenticateToken, async (req, res) => {
  const { status } = req.body;
  const { id } = req.params;

  try {
    await query("UPDATE registrations SET status = $1 WHERE id = $2", [status, id]);

    if (status === 'paid') {
      const regResult = await query(
        `SELECT r.*, u.email, u.name as user_name 
         FROM registrations r 
         JOIN users u ON r.user_id = u.id 
         WHERE r.id = $1`, 
        [id]
      );
      
      const reg = regResult.rows[0];

      if (reg && reg.email) {
        const subject = `Inscrição Confirmada - ${reg.pilot_name}`;
        const text = `
          Olá ${reg.user_name},
          
          O pagamento da sua inscrição foi confirmado!
          
          Evento: Tamura Eventos
          Piloto: ${reg.pilot_name}
          Moto: #${reg.pilot_number}
          Categorias: ${reg.categories}
          
          Nos vemos na pista! 🏁
        `;
        
        await sendEmail(reg.email, subject, text);
        console.log(`Email de confirmação enviado para ${reg.email}`);
      }
    }

    res.json({ message: "Status atualizado com sucesso!" });
  } catch (err) {
    console.error("Erro ao atualizar status:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/registrations/user/:userId', authenticateToken, async (req, res) => {
    try {
        const result = await query("SELECT * FROM registrations WHERE user_id = $1 ORDER BY created_at DESC", [req.params.userId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/registrations/stage/:stageId', authenticateToken, async (req, res) => {
    try {
        const result = await query(
            `SELECT 
                r.*, 
                u.phone, u.cpf, u.rg, u.medical_insurance, u.team,
                u.emergency_phone, u.address, u.email, u.birth_date, u.chip_id,
                u.modelo_moto  -- <--- IMPORTANTE: Adicionei isso aqui para o PDF pegar
             FROM registrations r 
             LEFT JOIN users u ON r.user_id = u.id 
             WHERE r.stage_id = $1 
             ORDER BY r.pilot_name ASC`, 
            [req.params.stageId]
        );
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/registrations/:id', authenticateToken, async (req, res) => {
    const registrationId = req.params.id;
    const userId = req.user.id; 

    try {
        const regResult = await query("SELECT user_id, status FROM registrations WHERE id = $1", [registrationId]);
        const registration = regResult.rows[0];

        if (!registration) {
            return res.status(404).json({ error: "Inscrição não encontrada." });
        }

        const isOwner = registration.user_id === userId;
        const isAdmin = req.user.role === 'admin';

        if (!isOwner && !isAdmin) {
            return res.status(403).json({ error: "Você não tem permissão para cancelar esta inscrição." });
        }

        if (registration.status === 'paid' && !isAdmin) {
             return res.status(400).json({ error: "Inscrições pagas só podem ser canceladas pelo administrador (para fins de reembolso)." });
        }
        
        await query("DELETE FROM registrations WHERE id = $1", [registrationId]);
        
        res.json({ message: "Inscrição cancelada com sucesso. O piloto pode se inscrever novamente." });

    } catch (err) {
        console.error("Erro ao cancelar inscrição:", err);
        res.status(500).json({ error: err.message });
    }
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

app.post('/api/stages/:id/upload/:category', authenticateToken, uploadFile.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Sem arquivo." });
  const client = await pool.connect();
  
  try {
    const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const data = xlsx.utils.sheet_to_json(sheet, { header: 1, defval: "" });
    
    let headerRowIndex = -1;
    let colMap = {}; 

    const synonyms = {
      'pos': 'position', 'p': 'position',
      'epc': 'epc',
      'nº': 'pilot_number', 'no': 'pilot_number', 'num': 'pilot_number',
      'piloto': 'pilot_name', 'nome': 'pilot_name',
      'v': 'laps', 'vlt': 'laps', 'voltas': 'voltas',
      'tempo corrido': 'race_time',
      'tempo total': 'total_time',
      'ultima volta': 'last_lap', 'última volta': 'last_lap',
      'dif. primeiro': 'diff_first', 'dif primeiro': 'diff_first',
      'dif. anterior': 'diff_prev', 'dif anterior': 'diff_prev',
      'melhor volta': 'best_lap',
      'v.m.': 'avg_speed', 'vm': 'avg_speed', 'velocidade': 'avg_speed'
    };

    for (let i = 0; i < Math.min(data.length, 30); i++) {
      const row = data[i].map(cell => (cell ? cell.toString().trim().toLowerCase() : ''));
      if (row.includes('piloto') && (row.includes('nº') || row.includes('no') || row.includes('num'))) {
        headerRowIndex = i;
        row.forEach((colName, index) => {
          if (synonyms[colName]) {
            colMap[synonyms[colName]] = index;
          }
        });
        break;
      }
    }

    if (headerRowIndex === -1) {
      throw new Error("Não foi possível encontrar o cabeçalho da tabela (procurei por 'Piloto' e 'Nº').");
    }

    const resultsToSave = [];

    for (let i = headerRowIndex + 1; i < data.length; i++) {
      const row = data[i];
      const getVal = (key, defaultIdx) => {
        const idx = colMap[key];
        return (idx !== undefined && row[idx] !== undefined) ? row[idx] : (row[defaultIdx] || '');
      };

      const rawPos = getVal('position', 0); 
      const pos = parseInt(rawPos);

      if (!isNaN(pos)) {
        resultsToSave.push({
          stage_id: req.params.id,
          position: pos,
          epc: getVal('epc', 2),
          pilot_number: getVal('pilot_number', 3),
          pilot_name: getVal('pilot_name', 4),
          category: req.params.category, 
          laps: getVal('laps', 8), 
          total_time: getVal('total_time', 9),
          last_lap: getVal('last_lap', 12),
          diff_first: getVal('diff_first', 13),
          diff_prev: getVal('diff_prev', 16),
          best_lap: getVal('best_lap', 18),
          avg_speed: getVal('avg_speed', 24),
          points: getPointsByPosition(pos)
        });
      }
    }

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
    
    res.json({ message: "Importado com sucesso!", count: resultsToSave.length, data: resultsToSave });

  } catch (error) { 
      await client.query('ROLLBACK');
      console.error("Erro no upload:", error); 
      res.status(500).json({ error: "Erro no processamento: " + error.message }); 
  } finally {
      client.release();
  }
});

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

app.put('/api/registrations/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { categories, pilot_number, total_price, pilot_name } = req.body;
  
  if (req.user.role !== 'admin') {
      return res.status(403).json({ error: "Apenas administradores podem editar inscrições." });
  }

  try {
      await query(
          `UPDATE registrations 
           SET categories = $1, pilot_number = $2, total_price = $3, pilot_name = $4 
           WHERE id = $5`,
          [categories, pilot_number, total_price, pilot_name, id]
      );
      res.json({ message: "Inscrição atualizada com sucesso!" });
  } catch (err) {
      console.error("Erro ao atualizar inscrição:", err);
      res.status(500).json({ error: err.message });
  }
});


// =====================================================
// ROTAS DE CATEGORIAS (CRUD)
// =====================================================

app.get('/api/categories', async (req, res) => {
    try {
        const result = await query("SELECT * FROM categories ORDER BY name ASC");
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/categories', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Acesso negado." });
    
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: "Nome é obrigatório." });

    try {
        const result = await query(
            "INSERT INTO categories (name) VALUES ($1) RETURNING *", 
            [name]
        );
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: "Categoria já existe." });
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/categories/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Acesso negado." });

    const { name } = req.body;
    try {
        await query("UPDATE categories SET name = $1 WHERE id = $2", [name, req.params.id]);
        res.json({ message: "Categoria atualizada!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Acesso negado." });

    try {
        await query("DELETE FROM categories WHERE id = $1", [req.params.id]);
        res.json({ message: "Categoria removida!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


app.listen(port, () => {
  console.log(`Tamura API Rodando na porta ${port}`);
});

module.exports = app;
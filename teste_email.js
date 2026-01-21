const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'enzopyton24@gmail.com',
    pass: 'fdiwxdqvnlqawgrg' 
  }
});

console.log("Tentando enviar email de teste...");

transporter.sendMail({
  from: 'enzopyton24@gmail.com',
  to: 'enzopyton24@gmail.com', // envia para você mesmo
  subject: 'Teste de Conexão Direta',
  text: 'Se você recebeu isso, o problema é no carregamento do .env ou no PM2.'
})
.then(info => console.log("✅ SUCESSO:", info.response))
.catch(err => console.error("❌ ERRO DETALHADO:", err));
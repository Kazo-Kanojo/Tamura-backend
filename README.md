# 🏆 Projeto Tamura

O **Tamura** é um sistema completo desenvolvido para o gerenciamento de eventos, usuários e visualização de tabelas de classificação (standings). A aplicação é dividida em uma interface de usuário moderna (Frontend) e uma API robusta (Backend), garantindo alta performance e segurança.

---

## 🚀 Tecnologias Utilizadas e Infraestrutura

A infraestrutura do projeto foi pensada para ser ágil e escalável, utilizando as seguintes tecnologias e serviços:

### 📱 Frontend (Vercel)
- **React.js** com **Vite** para um build rápido e otimizado.
- **Tailwind CSS** para estilização responsiva.
- **PWA (Progressive Web App)** via Workbox, permitindo instalação no dispositivo e uso offline.
- **Hospedagem:** Vercel (com configuração `vercel.json` para roteamento SPA).

### ⚙️ Backend (Hostinger)
- **Node.js** para a criação da API REST.
- **Hospedagem:** Hostinger (servidor VPS/Web).
- **Uploads:** Gerenciamento nativo de arquivos locais (armazenamento de imagens e leitura de planilhas CSV na pasta `/uploads`).

### 🗄️ Banco de Dados (Neon)
- **Neon (PostgreSQL Serverless)**: Banco de dados relacional em nuvem, oferecendo alta disponibilidade.

---

## 📁 Estrutura do Sistema

O sistema atende a diferentes perfis de acesso:
- **Administradores:** Acesso ao `AdminDashboard` para criar eventos, gerenciar usuários e fazer upload de planilhas de resultados.
- **Usuários:** Acesso ao `UserDashboard` para visualizar seus dados.
- **Público/Geral:** Visualização de Eventos (`EventCard`) e Tabelas de Classificação (`Standings`).

---

## 🛠️ Como executar o projeto localmente

Para rodar o projeto na sua máquina, você precisará configurar o Backend e o Frontend separadamente. Certifique-se de ter o [Node.js](https://nodejs.org/) instalado.

### 1. Configurando o Backend (API)

1. Entre na pasta do backend:
   ```bash
      cd tamura-backend

2. Instale as dependências:
   ```bash
      npm install

3. Crie um arquivo .env na raiz do backend (use o .env.example como base) e adicione a URL do banco Neon:

4. "Ligue a api"
    ```bash
       npx nodemon server.js
   
### 2. Configurando o Frontend (Interface)
   
1.Entre na pasta do projeto
   ```bash
      cd frontend
```

2. INstale as dependencias:
   ```bash
      npm install

3. Configure as variaveis de ambiente:
   ```bash
      cd tamura-backend

4. Inicie o projeto:
   ```bash
      npm run dev


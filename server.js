const express = require('express');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

require('dotenv').config({ path: path.resolve(__dirname, '.env') });
process.env.JWT_SECRET = process.env.JWT_SECRET || 'chave_reserva_para_entrega_123';

const app = express();
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'loginP.html'));  //pagina de login/principal
});
app.use(express.static('public'));
app.use(express.json());

// --- BANCO DE DADOS ---
const db = new sqlite3.Database('./estoque.db', (err) => {
    if (err) console.error("Erro no banco:", err.message);
    else {
        console.log("📦 Conectado ao banco de dados SQLite.");
        // Tabela de Produtos
        db.run(`CREATE TABLE IF NOT EXISTS produtos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo TEXT,
            nome TEXT,
            quantidade INTEGER,
            validade TEXT
        )`);
        // Tabela de Usuários
        db.run(`CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT,
                email TEXT UNIQUE,
                senha TEXT,
                data_nascimento TEXT,
                resetToken TEXT
        )`);
    }
});

// --- MIDDLEWARE DE AUTENTICAÇÃO ---
const autenticarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ erro: "Acesso negado. Faça login." });

    const chaveSecreta = process.env.JWT_SECRET || 'chave_reserva_para_entrega_123';

    jwt.verify(token, chaveSecreta, (err, user) => {
        if (err) return res.status(403).json({ erro: "Token inválido ou expirado." });
        req.user = user;
        next();
    });
};

// --- ROTAS DE USUÁRIO (LOGIN/CADASTRO/RESET) ---

app.post('/api/auth/registrar', async (req, res) => {
    const { nome, email, senha, data_nascimento } = req.body;

    try {
        const senhaHash = await bcrypt.hash(senha, 10);
        
        const sql = `INSERT INTO usuarios (nome, email, senha, data_nascimento) VALUES (?, ?, ?, ?)`;
        const params = [nome, email, senhaHash, data_nascimento];

        db.run(sql, params, function(err) {
            if (err) {
                console.error("Erro ao registrar:", err.message);
                return res.status(400).json({ erro: "E-mail já cadastrado ou dados inválidos." });
            }
            res.json({ sucesso: true, mensagem: "Usuário criado com sucesso!", id: this.lastID });
        });
    } catch (e) {
        res.status(500).json({ erro: "Erro ao processar cadastro." });
    }
});

app.post('/api/auth/login', (req, res) => {
    const { email, senha } = req.body;
    db.get(`SELECT * FROM usuarios WHERE email = ?`, [email], async (err, user) => {
        if (err) return res.status(500).json({ erro: "Erro no servidor." });
        if (!user) return res.status(401).json({ erro: "Usuário não encontrado." });

        const senhaValida = await bcrypt.compare(senha, user.senha);
        if (!senhaValida) return res.status(401).json({ erro: "Senha incorreta." });

        const chaveSecreta = process.env.JWT_SECRET || 'chave_reserva_para_entrega_123';
        const token = jwt.sign({ id: user.id, email: user.email }, chaveSecreta, { expiresIn: '2h' });
        res.json({ sucesso: true, token });
    });
});

app.post('/api/auth/esqueci-senha', (req, res) => {
    const { email } = req.body;
    const tokenReset = Math.random().toString(36).substring(2, 10);

    db.run(`UPDATE usuarios SET resetToken = ? WHERE email = ?`, [tokenReset, email], function(err) {
        if (err || this.changes === 0) return res.status(404).json({ erro: "E-mail não encontrado." });

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Recuperação de Senha - Despensa Inteligente',
            text: `Seu código de recuperação é: ${tokenReset}. Use-o para redefinir sua senha.`
        };

        transporter.sendMail(mailOptions, (error) => {
            if (error) {
                console.error("Erro e-mail:", error);
                return res.status(500).json({ erro: "Erro ao enviar e-mail.", detalhe: error.message });
            }
            res.json({ sucesso: true, mensagem: "E-mail enviado com sucesso!" });
        });
    });
});

app.post('/api/auth/redefinir-senha', async (req, res) => {
    const { email, token, novaSenha } = req.body;

    if (!email || !token || !novaSenha) {
        return res.status(400).json({ erro: "Todos os campos são obrigatórios." });
    }

    db.get(`SELECT * FROM usuarios WHERE email = ? AND resetToken = ?`, [email, token], async (err, user) => {
        if (err) {
            return res.status(500).json({ erro: "Erro ao consultar o banco de dados." });
        }
        
        if (!user) {
            return res.status(400).json({ erro: "E-mail ou código de recuperação inválido." });
        }

        try {
            const novaSenhaHash = await bcrypt.hash(novaSenha, 10);

            db.run(`UPDATE usuarios SET senha = ?, resetToken = NULL WHERE email = ?`, [novaSenhaHash, email], function(err) {
                if (err) {
                    return res.status(500).json({ erro: "Erro ao atualizar a senha no banco." });
                }
                res.json({ sucesso: true, mensagem: "Senha alterada com sucesso!" });
            });
        } catch (e) {
            res.status(500).json({ erro: "Erro ao processar a nova senha." });
        }
    });
});

// --- ROTAS DE PRODUTOS (PROTEGIDAS) ---

app.get('/api/produto/:codigo', autenticarToken, async (req, res) => {
    const codigo = req.params.codigo.replace(/\D/g, "");

    try {
        const url = `https://br.openfoodfacts.org/api/v0/product/${codigo}.json`;
        const response = await axios.get(url, {
            headers: { 'User-Agent': 'MinhaDespensaApp - Node - Versao1.0' }
        });

        if (response.data && response.data.status === 1) {
            const nomeProduto = response.data.product.product_name_pt || response.data.product.product_name;
            res.json({ encontrado: true, nome: nomeProduto });
        } else {
            res.json({ encontrado: false });
        }
    } catch (error) {
        console.error("Erro na busca:", error.message);
        res.status(500).json({ erro: "Erro na API externa" });
    }
});

app.get('/api/estoque', autenticarToken, (req, res) => {
    db.all(`SELECT * FROM produtos`, [], (err, rows) => {
        if (err) res.status(500).json({ erro: err.message });
        else res.json(rows);
    });
});

app.post('/api/estoque', autenticarToken, (req, res) => {
    const { codigo, nome, quantidade, validade } = req.body;
    db.run(`INSERT INTO produtos (codigo, nome, quantidade, validade) VALUES (?, ?, ?, ?)`, 
    [codigo, nome, quantidade, validade], function(err) {
        if (err) res.status(500).json({ erro: err.message });
        else res.json({ sucesso: true, id: this.lastID });
    });
});

app.put('/api/estoque/:id', autenticarToken, (req, res) => {
    const { quantidade, validade } = req.body;
    db.run(`UPDATE produtos SET quantidade = ?, validade = ? WHERE id = ?`, 
    [quantidade, validade, req.params.id], (err) => {
        if (err) res.status(500).json({ erro: err.message });
        else res.json({ sucesso: true });
    });
});

app.delete('/api/estoque/:id', autenticarToken, (req, res) => {
    db.run(`DELETE FROM produtos WHERE id = ?`, req.params.id, (err) => {
        if (err) res.status(500).json({ erro: err.message });
        else res.json({ sucesso: true });
    });
});

// --- GERAÇÃO DE RECEITA COM IA ---
const OpenAI = require("openai");

const groq = new OpenAI({
    apiKey: process.env.GROQ_API_KEY,
    baseURL: "https://api.groq.com/openai/v1"
});

/* ALTERADO: Ajustado o prompt JSON para incluir tempo, dificuldade e porcoes que seu HTML precisa */
app.get('/receita/:produto', autenticarToken, async (req, res) => {
    const produto = req.params.produto;

    try {
        const resposta = await groq.chat.completions.create({
            model: "llama-3.3-70b-versatile",
            messages: [
                {
                    role: "user",
                    content:
`Crie uma receita detalhada com o prato ou ingrediente: ${produto}.
Responda APENAS em formato JSON seguindo estritamente este modelo:
{
  "nome": "Nome da receita",
  "tempo": "25 min",
  "dificuldade": "Fácil",
  "porcoes": "2",
  "ingredientes": ["item 1", "item 2"],
  "preparo": ["passo 1", "passo 2"]
}`
                }
            ]
        });

        let textoIA = resposta.choices[0].message.content;

        textoIA = textoIA
            .replace(/```json/g, "")
            .replace(/```/g, "")
            .trim();

        const receita = JSON.parse(textoIA);
        res.json(receita);

    } catch (error) {
        console.log(error);
        res.status(500).json({ erro: "Erro na IA" });
    }
});

// --- ROTA DE SUGESTÕES DE RECEITAS ---
app.get('/api/sugestoes', autenticarToken, async (req, res) => {
    const { ingrediente } = req.query;
    if (!ingrediente) return res.status(400).json({ erro: "Ingrediente vazio" });

    try {
        const resposta = await groq.chat.completions.create({
            model: "llama-3.3-70b-versatile",
            messages: [{
                role: "user",
                content: `Retorne um array JSON com 3 receitas curtas de "${ingrediente}". 
                Use este formato exato: [{"nome": "X", "tempo": "Y"}]. 
                Não escreva mais nada além do JSON.`
            }]
        });

        let textoIA = resposta.choices[0].message.content;

        const inicio = textoIA.indexOf('[');
        const fim = textoIA.lastIndexOf(']') + 1;
        
        if (inicio === -1 || fim === 0) {
            throw new Error("IA não devolveu um JSON válido");
        }
        
        const jsonLimpo = textoIA.substring(inicio, fim);
        const sugestoes = JSON.parse(jsonLimpo);
        res.json(sugestoes);

    } catch (error) {
        console.error("Erro no Servidor:", error.message);
        res.status(500).json({ erro: "Erro ao processar receitas" });
    }
});

// Rota para buscar dados do perfil do usuário logado
app.get('/api/usuario/meu-perfil', autenticarToken, (req, res) => {
    const userId = req.user.id;

    db.get(`SELECT nome, email, data_nascimento FROM usuarios WHERE id = ?`, [userId], (err, user) => {
        if (err) {
            console.error("Erro ao buscar perfil:", err.message);
            return res.status(500).json({ erro: "Erro no servidor ao buscar perfil." });
        }
        if (!user) {
            return res.status(404).json({ erro: "Usuário não encontrado." });
        }
        res.json(user);
    });
});

/* ADICIONADO: Rota para servir a sua página receitaP.html de forma segura */
app.get('/receitaP.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'receitaP.html'));
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`✅ Servidor rodando em: http://localhost:${PORT}`);
});
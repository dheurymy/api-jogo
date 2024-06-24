import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import dotenv from 'dotenv';

dotenv.config();

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || 'default_secret';

app.use(cors());
app.use(express.json());

// Middleware para validação de token JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato Bearer

  if (!token) {
    return res.status(401).json({ error: 'Nenhum token fornecido' });
  }

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido ou expirado' });
    }
    req.userId = decoded.id;
    next();
  });
}

// Rota de cadastro (não precisa de autenticação)
app.post('/user/register', async (req, res) => {
  const { name, username, age, email, gender, password, knowledgeLevel, reasonsWhy } = req.body;

  try {
    // Verificar se o email já está em uso
    const existingEmail = await prisma.users.findUnique({ where: { email } });
    if (existingEmail) {
      return res.status(409).json({ error: 'Email já em uso' });
    }

    // Verificar se o username já está em uso
    const existingUsername = await prisma.users.findUnique({ where: { username } });
    if (existingUsername) {
      return res.status(409).json({ error: 'Nome de usuário já em uso' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.users.create({
      data: {
        name,
        username,
        age,
        email,
        gender,
        knowledgeLevel,
        reasonsWhy,
        password: hashedPassword,
      },
    });

    res.status(201).json({ message: 'Usuário criado', user });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota de login (não precisa de autenticação)
app.post('/user/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios' });
  }

  try {
    const user = await prisma.users.findUnique({ where: { email } });
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    const verifyPassword = await bcrypt.compare(password, user.password);
    if (!verifyPassword) {
      return res.status(401).json({ error: 'Senha inválida' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '1h' });

    res.status(200).json({ message: 'Logado com sucesso', token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Outras rotas protegidas (precisam de autenticação)
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Esta é uma rota protegida' });
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

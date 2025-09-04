import express from 'express'
import bcrypt from 'bcrypt'
import { PrismaClient } from '@prisma/client'
import jwt from 'jsonwebtoken'


const prisma = new PrismaClient()
const router = express.Router()

const JWT_SECRET = process.env.JWT_SECRET

//cadastro
router.post('/cadastro', async (req, res) =>{

    try{
    const user = req.body;

    const salt = await bcrypt.genSalt(10)
    const hashPassword = await bcrypt.hash (user.password, salt)
    // Salvar usuário no banco de dados
    const userDB = await prisma.user.create({
        data:{
            name: user.name,
            email: user.email,
            password: hashPassword,
            title: user.title,
            content: user.content,
        },
    })
    // Retorna o usuário cadastrado ou uma mensagem de erro
    res.status(201).json(userDB)
    } catch (err) {
        res.status(500).json({message: "Erro ao cadastrar usuário"})
    }
})

//Login
router.post('/login', async (req, res) =>{

    try{
    const userInfo = req.body
    // Buscar o usuário no banco de dados
    const user = await prisma.user.findUnique({
        where:{
            email: userInfo.email
        },
    })
    // verificar se o usuario existe no banco 
    if (!user){
        return res.status(404).json({message: "Usuário não encontrado"})
    }
    // Compara a senha do banco de dados
    const isMatch = await bcrypt.compare(userInfo.password, user.password)
    // Mensagem de erro caso a senha esteja incorreta
    if (!isMatch) {
        return res.status(400).json({ message: "Senha inválida" })
    }

    //Gerar o token JWT
    const token = jwt.sign({id: user.id}, JWT_SECRET, {expiresIn:'10m'})

    // Se tudo estiver correto, retorna o token
    res.status(200).json(token)
    } catch (err){
        res.status(500).json({message: "Erro ao fazer Login"})
    }
})

export default router
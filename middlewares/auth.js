import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET

const auth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1]
    if(!token){
        return res.status(401).json({ message: 'Token não fornecido' })
    }
    try {
        const decoded = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET)
        
        req.userId = decoded.id 
        next()
    } catch (err) {
        console.error(err)
        return res.status(401).json({ message: 'Token inválido' })
    }
}

export default auth
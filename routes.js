import Router from '@koa/router'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'
import  Jwt  from 'jsonwebtoken'

export const  router = new Router()

const prisma = new PrismaClient() 

//recebe um pedido e retorna uma lista
router.get('/tweets', async ctx =>{
    const [, token] = ctx.request.headers?.authorization?.split(' ') || []//recebendo token criptografado

    if(!token){
        ctx.status = 401
        return
    }

    try{
        Jwt.verify(token, process.env.JWT_SECRET)
        const tweets =  await prisma.tweet.findMany({
            include: {
                user: true
            }
        })  //Promisse
        ctx.body = tweets
    }catch(error){
        if(typeof error === 'JsonWebTokenError'){
            ctx.status = 401
            return
        }
        
        ctx.status = 500
        return
    }

})

//recebe um dado e salva no banco
router.post('/tweets', async ctx =>{
    const [, token] = ctx.request.headers?.authorization?.split(' ') || []//recebendo token criptografado

    if(!token){
        ctx.status = 401
        return
    }

    try{
        const payload = Jwt.verify(token, process.env.JWT_SECRET)
        const tweet = await prisma.tweet.create({
        data: {
                userId: payload.sub,
                text: ctx.request.body.text
            }
        })
    
        ctx.body = tweet
    }catch(error){
        ctx.status = 401
        return
    }

})

//rota de cadastro
router.post('/signup', async ctx =>{
    const saltRounds = 10
    const password = bcrypt.hashSync(ctx.request.body.password, saltRounds)
    try{
        const user = await prisma.user.create({
            data: {
                name: ctx.request.body.name,
                userName: ctx.request.body.userName,
                email: ctx.request.body.email,
                password: password
            }
        })

        const accessToken = Jwt.sign({
            sub: user.id
        }, process.env.JWT_SECRET, { expiresIn: '24h'})

        ctx.body = {
            id: user.id,
            name: user.name,
            userName: user.userName,
            email: user.email,
            accessToken
        }
    }catch(error){
        if(error.meta && !error.meta.target){
            ctx.status = 422
            ctx.body =  "Email ou nome de Usuario ja existem!!"
            return
        }
        ctx.status = 500
        ctx.body = "Erro interno"
    }
    
})

router.get('/login', async ctx => {
    const [, token] = ctx.request.headers.authorization.split(' ') //recebendo token criptografado
    const [email, plainTextPassword] = Buffer.from(token, 'base64').toString().split(':') //descriptografando o token

    const user = await prisma.user.findUnique({
        where: {
             email: email 
            }
    })

    if(!user){
        ctx.status = 404
        return
    }

    const passwordMatch = bcrypt.compareSync(plainTextPassword, user.password)

    if(passwordMatch){
        const accessToken = Jwt.sign({
            sub: user.id
        }, process.env.JWT_SECRET, { expiresIn: '24h'}) //JWT_SECRET vem do arquivo .env por questao de segurança
        ctx.body = {
            id: user.id,
            name: user.name,
            userName: user.userName,
            email: user.email,
            accessToken: accessToken
        }
        return
    }

    ctx.status = 404

})
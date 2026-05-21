dotenv.config()
import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import cookieParser from 'cookie-parser'
import { createRequire } from 'module'

import { globalLimiter, authLimiter, emailLimiter } from './middleware/rateLimiter.js'
import { requestLogger } from './middleware/requestLogger.js'
import { errorHandler } from './middleware/errorHandler.js'
import { notFound } from './middleware/notFound.js'

import authRouter from './Routes/auth.js'

const require = createRequire(import.meta.url)
const { version } = require('./package.json')

const app = express()
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: ['http://192.168.66.142:5173', 'https://lunarcord.vercel.app', '192.168.66.142'], credentials: true }))
app.use(express.json())
app.set('trust proxy', 1)
app.use(cookieParser())
app.use(globalLimiter)
app.use(requestLogger)
app.use('/auth', authLimiter, authRouter)

app.get('/health', async (req, res) => { res.send('Ok') })

app.get('/', async (req, res) => {
    res.status(200).json({ status: 'online!', version: version })
})

app.use(errorHandler)
app.use(notFound)

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});




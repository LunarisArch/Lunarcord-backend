import { JwtUtility } from '../utils/JwtService.js'

export const authMiddleware = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' })
        }

        const token = authHeader.split(' ')[1]

        if (!token) {
            return res.status(401).json({ error: 'No token provided' })
        }

        const decoded = JwtUtility.verifyAccessToken(token)
        req.user = decoded
        next()
    } catch (error) {
        return res.status(401).json({ error: error.message })
    }
}

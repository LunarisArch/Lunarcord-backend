import jwt from 'jsonwebtoken'
import crypto from 'crypto';

export class JwtUtility {
    static generateAccessToken(user) {
        const payload = { userId: user.id, username: user.username, email: user.email }
        return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN })
    }

    static generateRefreshToken() {
        return crypto.randomBytes(64).toString('hex');
    }
    static verifyAccessToken(token) {
        try {
            return jwt.verify(token, process.env.JWT_SECRET);
        } catch (error) {
            throw new Error('Invalid or expired access token');
        }
    }
}
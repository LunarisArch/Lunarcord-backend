import crypto from 'crypto'
import bcrypt from 'bcrypt'

export class CryptoUtility {
    static generateToken() {
        return crypto.randomBytes(32).toString('hex')
    }

    static async hashToken(token) {
        return await bcrypt.hash(token, 12)
    }

    // Use this when verifying email/reset tokens instead of calling bcrypt directly
    static async compareToken(plainToken, hashedToken) {
        return await bcrypt.compare(plainToken, hashedToken)
    }
}
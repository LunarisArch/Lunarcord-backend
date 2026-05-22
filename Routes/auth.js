import { Router } from 'express'
import bcrypt from 'bcrypt'
import supabase from '../utils/supabase.js'
import { JwtUtility } from '../utils/JwtService.js'
import { CryptoUtility } from '../utils/CryptoService.js'
import { sendVerificationEmail, sendPasswordResetEmail, sendPasswordChangedEmail } from '../utils/EmailService.js'
import { authMiddleware } from '../middleware/auth.js'
import { emailLimiter } from '../middleware/rateLimiter.js'

const router = Router()

const REFRESH_TOKEN_EXPIRES_DAYS = 30
const VERIFY_TOKEN_EXPIRES_HOURS = 24
const RESET_TOKEN_EXPIRES_HOURS = 1
const BCRYPT_ROUNDS = 12

// ─── Helper: set refresh token cookie ────────────────────────────────────────
function setRefreshCookie(res, token) {
    res.cookie('refreshToken', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000
    })
}

// ─── Helper: clear refresh token cookie ──────────────────────────────────────
function clearRefreshCookie(res) {
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    })
}

// ─── Helper: store refresh token in DB ───────────────────────────────────────
async function storeRefreshToken(userId, plainToken) {
    const tokenHash = await CryptoUtility.hashToken(plainToken)
    const expiresAt = new Date()
    expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_EXPIRES_DAYS)

    const { error } = await supabase.from('refresh_tokens').insert({
        user_id: userId,
        token_hash: tokenHash,
        expires_at: expiresAt.toISOString(),
        revoked: false
    })

    if (error) throw new Error('Failed to store refresh token')
}

// ─── Helper: store email token in DB ─────────────────────────────────────────
async function storeEmailToken(userId, plainToken, type, expiresInHours) {
    const tokenHash = await CryptoUtility.hashToken(plainToken)
    const expiresAt = new Date()
    expiresAt.setHours(expiresAt.getHours() + expiresInHours)

    const { error } = await supabase.from('email_tokens').insert({
        user_id: userId,
        token_hash: tokenHash,
        type,
        expires_at: expiresAt.toISOString(),
        used: false
    })

    if (error) throw new Error('Failed to store email token')
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/register
// ─────────────────────────────────────────────────────────────────────────────
router.post('/register', async (req, res) => {
    try {
        const { email, username, password } = req.body

        if (!email || !username || !password) {
            return res.status(400).json({ error: 'Email, username and password are required' })
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' })
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' })
        }

        const { data: existingEmail } = await supabase
            .from('users')
            .select('id')
            .eq('email', email.toLowerCase())
            .single()

        if (existingEmail) {
            return res.status(409).json({ error: 'Email already in use' })
        }

        const { data: existingUsername } = await supabase
            .from('users')
            .select('id')
            .eq('username', username)
            .single()

        if (existingUsername) {
            return res.status(409).json({ error: 'Username already taken' })
        }

        const password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS)

        const { data: newUser, error: insertError } = await supabase
            .from('users')
            .insert({
                email: email.toLowerCase(),
                username,
                password_hash,
                is_verified: false
            })
            .select('id, email, username, is_verified, created_at')
            .single()

        if (insertError) throw insertError

        const verifyToken = CryptoUtility.generateToken()
        await storeEmailToken(newUser.id, verifyToken, 'verify_email', VERIFY_TOKEN_EXPIRES_HOURS)
        await sendVerificationEmail(newUser.email, verifyToken)

        const accessToken = JwtUtility.generateAccessToken(newUser)
        const refreshToken = JwtUtility.generateRefreshToken()
        await storeRefreshToken(newUser.id, refreshToken)
        setRefreshCookie(res, refreshToken)

        return res.status(201).json({
            accessToken,
            user: {
                id: newUser.id,
                email: newUser.email,
                username: newUser.username,
                isVerified: newUser.is_verified
            }
        })
    } catch (error) {
        console.error('[Auth] Register error:', error.message)
        return res.status(500).json({ error: 'Internal server error' })
    }
})

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/login
// ─────────────────────────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' })
        }

        const { data: user } = await supabase
            .from('users')
            .select('id, email, username, password_hash, is_verified')
            .eq('email', email.toLowerCase())
            .single()

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' })
        }

        const passwordMatch = await bcrypt.compare(password, user.password_hash)
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' })
        }

        if (!user.is_verified) {
            return res.status(403).json({
                error: 'Please verify your email before logging in',
                code: 'EMAIL_NOT_VERIFIED'
            })
        }

        const accessToken = JwtUtility.generateAccessToken(user)
        const refreshToken = JwtUtility.generateRefreshToken()
        await storeRefreshToken(user.id, refreshToken)
        setRefreshCookie(res, refreshToken)

        return res.status(200).json({
            accessToken,
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                isVerified: user.is_verified
            }
        })
    } catch (error) {
        console.error('[Auth] Login error:', error.message)
        return res.status(500).json({ error: 'Internal server error' })
    }
})

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/refresh
// ─────────────────────────────────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
    try {
        const plainToken = req.cookies?.refreshToken

        if (!plainToken) {
            return res.status(401).json({ error: 'No refresh token provided' })
        }

        const { data: tokens } = await supabase
            .from('refresh_tokens')
            .select('id, user_id, token_hash, expires_at, revoked')
            .eq('revoked', false)
            .gt('expires_at', new Date().toISOString())

        if (!tokens || tokens.length === 0) {
            return res.status(401).json({ error: 'Invalid refresh token' })
        }

        let matchedToken = null
        for (const token of tokens) {
            const isMatch = await CryptoUtility.compareToken(plainToken, token.token_hash)
            if (isMatch) { matchedToken = token; break }
        }

        if (!matchedToken) {
            return res.status(401).json({ error: 'Invalid refresh token' })
        }

        const { data: user } = await supabase
            .from('users')
            .select('id, email, username, is_verified')
            .eq('id', matchedToken.user_id)
            .single()

        if (!user) {
            return res.status(401).json({ error: 'User not found' })
        }

        await supabase.from('refresh_tokens').update({ revoked: true }).eq('id', matchedToken.id)
        const newRefreshToken = JwtUtility.generateRefreshToken()
        await storeRefreshToken(user.id, newRefreshToken)
        setRefreshCookie(res, newRefreshToken)

        const accessToken = JwtUtility.generateAccessToken(user)
        return res.status(200).json({ accessToken })
    } catch (error) {
        console.error('[Auth] Refresh error:', error.message)
        return res.status(500).json({ error: 'Internal server error' })
    }
})

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/logout
// ─────────────────────────────────────────────────────────────────────────────
router.post('/logout', async (req, res) => {
    try {
        const plainToken = req.cookies?.refreshToken

        if (plainToken) {
            const { data: tokens } = await supabase
                .from('refresh_tokens')
                .select('id, token_hash')
                .eq('revoked', false)

            if (tokens) {
                for (const token of tokens) {
                    const isMatch = await CryptoUtility.compareToken(plainToken, token.token_hash)
                    if (isMatch) {
                        await supabase.from('refresh_tokens').update({ revoked: true }).eq('id', token.id)
                        break
                    }
                }
            }
        }

        clearRefreshCookie(res)
        return res.status(200).json({ message: 'Logged out successfully' })
    } catch (error) {
        console.error('[Auth] Logout error:', error.message)
        return res.status(500).json({ error: 'Internal server error' })
    }
})

// ─────────────────────────────────────────────────────────────────────────────
// GET /auth/verify-email
// ─────────────────────────────────────────────────────────────────────────────
router.get('/verify-email', async (req, res) => {
    try {
        const { token } = req.query

        if (!token) {
            return res.status(400).json({ error: 'Token is required' })
        }

        const { data: tokens, error: fetchError } = await supabase
            .from('email_tokens')
            .select('id, user_id, token_hash, expires_at, used')
            .eq('type', 'verify_email')
            .eq('used', false)

        if (fetchError || !tokens || tokens.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired verification link' })
        }

        let matchedToken = null
        for (const t of tokens) {
            const isMatch = await CryptoUtility.compareToken(token, t.token_hash)
            if (isMatch) { matchedToken = t; break }
        }

        if (!matchedToken) {
            return res.status(400).json({ error: 'Invalid or expired verification link' })
        }

        if (new Date(matchedToken.expires_at) < new Date()) {
            return res.status(400).json({ error: 'Verification link has expired. Please request a new one.' })
        }

        res.set('Cache-Control', 'no-store')

        await supabase.from('email_tokens').update({ used: true }).eq('id', matchedToken.id)
        await supabase.from('users').update({ is_verified: true }).eq('id', matchedToken.user_id)

        return res.status(200).json({ message: 'Email verified successfully' })

    } catch (error) {
        console.error('[Auth] Verify email error:', error.message)
        return res.status(500).json({ error: 'Internal server error' })
    }
})

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/resend-verification
// ─────────────────────────────────────────────────────────────────────────────
router.post('/resend-verification', emailLimiter, async (req, res) => {
    try {
        const { email } = req.body

        if (!email) {
            return res.status(400).json({ error: 'Email is required' })
        }

        const { data: user } = await supabase
            .from('users')
            .select('id, email, is_verified')
            .eq('email', email.toLowerCase())
            .single()

        if (!user) {
            return res.status(400).json({ error: 'No account found with that email' })
        }

        if (user.is_verified) {
            return res.status(400).json({ error: 'Account is already verified' })
        }

        await supabase
            .from('email_tokens')
            .delete()
            .eq('user_id', user.id)
            .eq('type', 'verify_email')
            .eq('used', false)

        const verifyToken = CryptoUtility.generateToken()
        await storeEmailToken(user.id, verifyToken, 'verify_email', VERIFY_TOKEN_EXPIRES_HOURS)
        await sendVerificationEmail(user.email, verifyToken)

        return res.status(200).json({ message: 'Verification email sent' })
    } catch (error) {
        console.error('[Auth] Resend verification error:', error.message)
        return res.status(500).json({ error: 'Internal server error' })
    }
})

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/forgot-password
// ─────────────────────────────────────────────────────────────────────────────
router.post('/forgot-password', emailLimiter, async (req, res) => {
    try {
        const { email } = req.body

        if (!email) {
            return res.status(200).json({ message: 'If that email exists you will receive a reset link' })
        }

        const { data: user } = await supabase
            .from('users')
            .select('id, email')
            .eq('email', email.toLowerCase())
            .single()

        if (user) {
            await supabase
                .from('email_tokens')
                .delete()
                .eq('user_id', user.id)
                .eq('type', 'reset_password')
                .eq('used', false)

            const resetToken = CryptoUtility.generateToken()
            await storeEmailToken(user.id, resetToken, 'reset_password', RESET_TOKEN_EXPIRES_HOURS)
            await sendPasswordResetEmail(user.email, resetToken)
        }

        return res.status(200).json({ message: 'If that email exists you will receive a reset link' })
    } catch (error) {
        console.error('[Auth] Forgot password error:', error.message)
        return res.status(500).json({ error: 'Internal server error' })
    }
})

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/reset-password
// ─────────────────────────────────────────────────────────────────────────────
router.post('/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body

        if (!token || !newPassword) {
            return res.status(400).json({ error: 'Token and new password are required' })
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' })
        }

        const { data: tokens } = await supabase
            .from('email_tokens')
            .select('id, user_id, token_hash')
            .eq('type', 'reset_password')
            .eq('used', false)
            .gt('expires_at', new Date().toISOString())

        if (!tokens || tokens.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired reset link' })
        }

        let matchedToken = null
        for (const t of tokens) {
            const isMatch = await CryptoUtility.compareToken(token, t.token_hash)
            if (isMatch) { matchedToken = t; break }
        }

        if (!matchedToken) {
            return res.status(400).json({ error: 'Invalid or expired reset link' })
        }

        const password_hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS)

        await supabase.from('users').update({ password_hash }).eq('id', matchedToken.user_id)
        await supabase.from('email_tokens').update({ used: true }).eq('id', matchedToken.id)
        await supabase.from('refresh_tokens').update({ revoked: true }).eq('user_id', matchedToken.user_id)

        const { data: user } = await supabase
            .from('users')
            .select('email')
            .eq('id', matchedToken.user_id)
            .single()

        if (user) await sendPasswordChangedEmail(user.email)

        return res.status(200).json({ message: 'Password reset successfully' })
    } catch (error) {
        console.error('[Auth] Reset password error:', error.message)
        return res.status(500).json({ error: 'Internal server error' })
    }
})

// ─────────────────────────────────────────────────────────────────────────────
// GET /auth/me  (protected)
// ─────────────────────────────────────────────────────────────────────────────
router.get('/me', authMiddleware, async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('id, email, username, avatar_url, is_verified, created_at')
            .eq('id', req.user.userId)
            .single()

        if (error || !user) {
            return res.status(404).json({ error: 'User not found' })
        }

        return res.status(200).json({ user })
    } catch (error) {
        console.error('[Auth] Me error:', error.message)
        return res.status(500).json({ error: 'Internal server error' })
    }
})

export default router
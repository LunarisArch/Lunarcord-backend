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

// ─── Helpers ─────────────────────────────────────────────────────────────────
function setRefreshCookie(res, token) {
    res.cookie('refreshToken', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000
    })
}

function clearRefreshCookie(res) {
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    })
}

async function storeRefreshToken(userId, rawToken) {
    const tokenHash = await CryptoUtility.hashToken(rawToken)
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

async function storeEmailToken(userId, rawToken, type, expiresInHours) {
    const tokenHash = await CryptoUtility.hashToken(rawToken)
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

        const { data: existingUser } = await supabase
            .from('users')
            .select('id, email, username')
            .or(`email.eq.${email.toLowerCase()},username.eq.${username}`)
            .single()

        if (existingUser) {
            const field = existingUser.email === email.toLowerCase() ? 'Email' : 'Username'
            return res.status(409).json({ error: `${field} already in use` })
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

        // Generate token and append userId so we can look it up instantly later
        const rawToken = CryptoUtility.generateToken()
        const clientToken = `${newUser.id}.${rawToken}`

        await storeEmailToken(newUser.id, rawToken, 'verify_email', VERIFY_TOKEN_EXPIRES_HOURS)
        await sendVerificationEmail(newUser.email, clientToken)

        // BUG FIX: Removed auto-login. Force user to verify email first.
        return res.status(201).json({
            message: 'Registration successful. Please check your email to verify your account.',
            user: {
                id: newUser.id,
                email: newUser.email,
                username: newUser.username
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

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Invalid credentials' })
        }

        if (!user.is_verified) {
            return res.status(403).json({
                error: 'Please verify your email before logging in',
                code: 'EMAIL_NOT_VERIFIED'
            })
        }

        const accessToken = JwtUtility.generateAccessToken(user)
        const rawRefresh = JwtUtility.generateRefreshToken()
        const clientRefresh = `${user.id}.${rawRefresh}`

        await storeRefreshToken(user.id, rawRefresh)
        setRefreshCookie(res, clientRefresh)

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
        const clientToken = req.cookies?.refreshToken
        if (!clientToken || !clientToken.includes('.')) {
            return res.status(401).json({ error: 'Invalid refresh token format' })
        }

        const [userId, rawToken] = clientToken.split('.')

        // BUG FIX: Now we only pull tokens for THIS specific user.
        const { data: tokens } = await supabase
            .from('refresh_tokens')
            .select('id, user_id, token_hash, expires_at, revoked')
            .eq('user_id', userId)
            .eq('revoked', false)
            .gt('expires_at', new Date().toISOString())

        if (!tokens || tokens.length === 0) {
            return res.status(401).json({ error: 'Invalid refresh token' })
        }

        let matchedToken = null
        for (const token of tokens) {
            if (await CryptoUtility.compareToken(rawToken, token.token_hash)) {
                matchedToken = token; break
            }
        }

        if (!matchedToken) return res.status(401).json({ error: 'Invalid refresh token' })

        const { data: user } = await supabase
            .from('users')
            .select('id, email, username, is_verified')
            .eq('id', matchedToken.user_id)
            .single()

        if (!user) return res.status(401).json({ error: 'User not found' })

        await supabase.from('refresh_tokens').update({ revoked: true }).eq('id', matchedToken.id)

        const newRawRefresh = JwtUtility.generateRefreshToken()
        const newClientRefresh = `${user.id}.${newRawRefresh}`

        await storeRefreshToken(user.id, newRawRefresh)
        setRefreshCookie(res, newClientRefresh)

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
        const clientToken = req.cookies?.refreshToken

        if (clientToken && clientToken.includes('.')) {
            const [userId, rawToken] = clientToken.split('.')

            const { data: tokens } = await supabase
                .from('refresh_tokens')
                .select('id, token_hash')
                .eq('user_id', userId)
                .eq('revoked', false)

            if (tokens) {
                for (const token of tokens) {
                    if (await CryptoUtility.compareToken(rawToken, token.token_hash)) {
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
        const clientToken = req.query.token

        if (!clientToken || !clientToken.includes('.')) {
            return res.status(400).json({ error: 'Invalid verification link format' })
        }

        const [userId, rawToken] = clientToken.split('.')

        const { data: tokens, error: fetchError } = await supabase
            .from('email_tokens')
            .select('id, user_id, token_hash, expires_at, used')
            .eq('user_id', userId)
            .eq('type', 'verify_email')

        if (fetchError || !tokens || tokens.length === 0) {
            return res.status(400).json({ error: 'Invalid verification link' })
        }

        let matchedToken = null
        for (const t of tokens) {
            if (await CryptoUtility.compareToken(rawToken, t.token_hash)) {
                matchedToken = t; break
            }
        }

        if (!matchedToken) return res.status(400).json({ error: 'Invalid verification link' })

        if (new Date(matchedToken.expires_at) < new Date()) {
            return res.status(400).json({ error: 'Verification link has expired.' })
        }

        if (matchedToken.used) {
            return res.status(200).json({ message: 'Email is already verified' })
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

        // BUG FIX: Prevent email enumeration by returning a generic message
        if (!user || user.is_verified) {
            return res.status(200).json({ message: 'If an unverified account exists with that email, a verification link has been sent.' })
        }

        await supabase
            .from('email_tokens')
            .delete()
            .eq('user_id', user.id)
            .eq('type', 'verify_email')
            .eq('used', false)

        const rawToken = CryptoUtility.generateToken()
        const clientToken = `${user.id}.${rawToken}`

        await storeEmailToken(user.id, rawToken, 'verify_email', VERIFY_TOKEN_EXPIRES_HOURS)
        await sendVerificationEmail(user.email, clientToken)

        return res.status(200).json({ message: 'If an unverified account exists with that email, a verification link has been sent.' })
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

            const rawToken = CryptoUtility.generateToken()
            const clientToken = `${user.id}.${rawToken}`

            await storeEmailToken(user.id, rawToken, 'reset_password', RESET_TOKEN_EXPIRES_HOURS)
            await sendPasswordResetEmail(user.email, clientToken)
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

        if (!token || !token.includes('.') || !newPassword) {
            return res.status(400).json({ error: 'Valid token and new password are required' })
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' })
        }

        const [userId, rawToken] = token.split('.')

        const { data: tokens } = await supabase
            .from('email_tokens')
            .select('id, user_id, token_hash')
            .eq('user_id', userId)
            .eq('type', 'reset_password')
            .eq('used', false)
            .gt('expires_at', new Date().toISOString())

        if (!tokens || tokens.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired reset link' })
        }

        let matchedToken = null
        for (const t of tokens) {
            if (await CryptoUtility.compareToken(rawToken, t.token_hash)) {
                matchedToken = t; break
            }
        }

        if (!matchedToken) return res.status(400).json({ error: 'Invalid or expired reset link' })

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
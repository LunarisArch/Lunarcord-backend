import fs from 'fs/promises'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

if (!process.env.BREVO_API_KEY) {
    console.error('[Email] BREVO_API_KEY is not set')
}

if (!process.env.BREVO_SENDER) {
    console.error('[Email] BREVO_SENDER is not set')
}

const SENDER_NAME = process.env.SMTP_FROM || 'Lunarcord'
const SENDER_EMAIL = process.env.BREVO_SENDER
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173'

async function getTemplate(templateName) {
    try {
        const filePath = path.join(__dirname, 'email-templates', `${templateName}.html`)
        return await fs.readFile(filePath, 'utf-8')
    } catch (error) {
        console.error(`[Email] Template "${templateName}" not found:`, error.message)
        throw new Error(`Email template "${templateName}" could not be loaded`)
    }
}

async function sendMail({ to, subject, html, text }) {
    try {
        const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'api-key': process.env.BREVO_API_KEY,
                'content-type': 'application/json'
            },
            body: JSON.stringify({
                sender: { name: SENDER_NAME, email: SENDER_EMAIL },
                to: [{ email: to }],
                subject,
                htmlContent: html,
                textContent: text
            })
        })

        if (!response.ok) {
            const err = await response.json()
            console.error('[Email] Brevo API error:', err)
            throw new Error(err.message || 'Brevo API request failed')
        }

        console.log(`[Email] Sent "${subject}" to ${to}`)
    } catch (error) {
        console.error('[Email] Failed to send to', to, ':', error.message)
        throw new Error('Failed to send email')
    }
}

export async function sendVerificationEmail(to, token) {
    // Plain hex token — no encoding needed, keeps it clean in the URL
    const verifyUrl = `${CLIENT_URL}/verify-email?token=${token}`
    let html = await getTemplate('verify')
    html = html.replace(/{{VERIFY_URL}}/g, verifyUrl)
    html = html.replace(/{{APP_URL}}/g, CLIENT_URL)

    await sendMail({
        to,
        subject: 'Lunarcord — Verify your email address',
        html,
        text: `Verify your Lunarcord email by visiting: ${verifyUrl}\n\nThis link expires in 24 hours.\n\nIf you didn't create an account, ignore this email.`
    })
}

export async function sendPasswordResetEmail(to, token) {
    const resetUrl = `${CLIENT_URL}/reset-password?token=${token}`
    let html = await getTemplate('reset-password')
    html = html.replace(/{{RESET_URL}}/g, resetUrl)
    html = html.replace(/{{APP_URL}}/g, CLIENT_URL)

    await sendMail({
        to,
        subject: 'Lunarcord — Password Reset Request',
        html,
        text: `Reset your Lunarcord password by visiting: ${resetUrl}\n\nThis link expires in 1 hour.\n\nIf you didn't request this, ignore this email.`
    })
}

export async function sendPasswordChangedEmail(to) {
    let html = await getTemplate('password-changed')
    html = html.replace(/{{APP_URL}}/g, CLIENT_URL)

    await sendMail({
        to,
        subject: 'Lunarcord — Security Alert: Your password has been updated',
        html,
        text: `Your Lunarcord password was recently changed. If this was you, no action is needed.\n\nIf you did not change your password, contact support immediately at ${CLIENT_URL}.`
    })
}

export async function sendEmailChangedEmail(to) {
    let html = await getTemplate('email-changed')
    html = html.replace(/{{APP_URL}}/g, CLIENT_URL)

    await sendMail({
        to,
        subject: 'Lunarcord — Security Alert: Account email address changed',
        html,
        text: `The email address on your Lunarcord account was recently changed. If this was you, no action is needed.\n\nIf you did not make this change, contact support immediately at ${CLIENT_URL}.`
    })
}
import nodemailer from 'nodemailer';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
    tls: {
        // Keeps local network configurations from dropping the secure handshake
        rejectUnauthorized: false
    }
});

transporter.verify((error) => {
    if (error) {
        console.error('[Email] SMTP connection failed:', error.message);
    } else {
        console.log('[Email] SMTP connection established');
    }
})

const FROM_EMAIL = process.env.SMTP_FROM || 'Lunarcord <systemslunaris@gmail.com>';
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';

async function getTemplate(templateName) {
    try {
        const filePath = path.join(__dirname, './email-templates', `${templateName}.html`);
        return await fs.readFile(filePath, 'utf-8');
    } catch (error) {
        console.error(`[Email] Template "${templateName}" not found:`, error.message);
        throw new Error(`Email template "${templateName}" could not be loaded`);
    }
}

async function sendMail(options) {
    try {
        await transporter.sendMail(options);
    } catch (error) {
        console.error('[Email] Failed to send email to', options.to, ':', error.message);
        throw new Error('Failed to send email');
    }
}

export async function sendVerificationEmail(to, token) {
    const verifyUrl = `${CLIENT_URL}/verify-email?token=${token}`;
    let html = await getTemplate('verify');
    html = html.replace(/{{VERIFY_URL}}/g, verifyUrl);
    html = html.replace(/{{APP_URL}}/g, CLIENT_URL);

    await sendMail({
        from: FROM_EMAIL,
        to,
        subject: 'Lunarcord — Verify your email address',
        html,
        text: `Verify your Lunarcord email by visiting this link: ${verifyUrl}\n\nThis link expires in 24 hours.\n\nIf you didn't create an account, ignore this email.`,
    });
}

export async function sendPasswordResetEmail(to, token) {
    const resetUrl = `${CLIENT_URL}/reset-password?token=${token}`;
    let html = await getTemplate('reset-password');
    html = html.replace(/{{RESET_URL}}/g, resetUrl);
    html = html.replace(/{{APP_URL}}/g, CLIENT_URL);

    await sendMail({
        from: FROM_EMAIL,
        to,
        subject: 'Lunarcord — Password Reset Request',
        html,
        text: `Reset your Lunarcord password by visiting: ${resetUrl}\n\nThis link expires in 1 hour.\n\nIf you didn't request this, ignore this email.`,
    });
}

export async function sendPasswordChangedEmail(to) {
    let html = await getTemplate('password-changed');
    html = html.replace(/{{APP_URL}}/g, CLIENT_URL);

    await sendMail({
        from: FROM_EMAIL,
        to,
        subject: 'Lunarcord — Security Alert: Your password has been updated',
        html,
        text: `Your Lunarcord password was recently changed. If this was you, no action is needed.\n\nIf you did not change your password, contact support immediately at ${CLIENT_URL}.`,
    });
}

export async function sendEmailChangedEmail(to) {
    let html = await getTemplate('email-changed');
    html = html.replace(/{{APP_URL}}/g, CLIENT_URL);

    await sendMail({
        from: FROM_EMAIL,
        to,
        subject: 'Lunarcord — Security Alert: Account email address changed',
        html,
        text: `The email address on your Lunarcord account was recently changed. If this was you, no action is needed.\n\nIf you did not make this change, contact support immediately at ${CLIENT_URL}.`,
    });
}
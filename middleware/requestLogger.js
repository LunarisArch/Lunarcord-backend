import supabase from '../utils/supabase.js'

export const requestLogger = async (req, res, next) => {
    const startTime = Date.now()

    // Capture the original res.json to intercept the response body
    const originalJson = res.json.bind(res)
    let responseBody = null

    res.json = (body) => {
        responseBody = body
        return originalJson(body)
    }

    // Log after response is finished
    res.on('finish', async () => {
        const duration = Date.now() - startTime

        // Sanitize request body — never log passwords or tokens
        const sanitizedBody = sanitizeBody(req.body)

        const logEntry = {
            method: req.method,
            path: req.path,
            status_code: res.statusCode,
            duration_ms: duration,
            ip: req.ip || req.headers['x-forwarded-for'] || 'unknown',
            user_agent: req.headers['user-agent'] || null,
            user_id: req.user?.userId || null,
            request_body: Object.keys(sanitizedBody).length > 0 ? sanitizedBody : null,
            response_body: sanitizeBody(responseBody),
            query_params: Object.keys(req.query).length > 0 ? req.query : null,
        }
        if (logEntry.path === '/health') { return }
        try {
            await supabase.from('request_logs').insert(logEntry)
        } catch (error) {
            // Never let logging crash the app
            console.error('[Logger] Failed to write log to Supabase:', error.message)
        }
    })

    next()
}

// Strip sensitive fields before logging
function sanitizeBody(body) {
    if (!body || typeof body !== 'object') return {}

    const sensitiveFields = [
        'password',
        'password_hash',
        'newPassword',
        'confirmPassword',
        'token',
        'accessToken',
        'refreshToken',
        'secret',
        'pass',
    ]

    const sanitized = { ...body }
    sensitiveFields.forEach(field => {
        if (sanitized[field] !== undefined) {
            sanitized[field] = '[REDACTED]'
        }
    })

    return sanitized
}

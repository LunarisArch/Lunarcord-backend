export const errorHandler = (err, req, res, next) => {
    console.error('[Error]', err.message)

    // Handle specific known error types
    if (err.name === 'ValidationError') {
        return res.status(400).json({ error: err.message })
    }

    if (err.name === 'UnauthorizedError') {
        return res.status(401).json({ error: 'Unauthorized' })
    }

    if (err.code === '23505') {
        // Supabase/Postgres unique constraint violation
        return res.status(409).json({ error: 'Resource already exists' })
    }

    if (err.code === '23503') {
        // Supabase/Postgres foreign key violation
        return res.status(400).json({ error: 'Referenced resource does not exist' })
    }

    // Generic fallback — never expose internal error details in production
    const isDev = process.env.NODE_ENV === 'development'
    return res.status(err.status || 500).json({
        error: isDev ? err.message : 'Internal server error'
    })
}

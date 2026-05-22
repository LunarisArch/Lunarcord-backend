// GET /auth/verify-email
router.get('/verify-email', async (req, res) => {
    try {
        const { token } = req.query

        if (!token) {
            return res.status(400).json({ error: 'Token is required' })
        }

        // Get all unused verify_email tokens — no expires_at filter so we can give better errors
        const { data: tokens, error: fetchError } = await supabase
            .from('email_tokens')
            .select('id, user_id, token_hash, expires_at, used')
            .eq('type', 'verify_email')
            .eq('used', false)

        if (fetchError) {
            console.error('[Verify] DB fetch error:', fetchError.message)
            return res.status(500).json({ error: 'Internal server error' })
        }

        if (!tokens || tokens.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired verification link' })
        }

        // Find matching token
        let matchedToken = null
        for (const t of tokens) {
            const isMatch = await CryptoUtility.compareToken(token, t.token_hash)
            if (isMatch) { matchedToken = t; break }
        }

        if (!matchedToken) {
            return res.status(400).json({ error: 'Invalid or expired verification link' })
        }

        // Check expiry manually after finding the match
        if (new Date(matchedToken.expires_at) < new Date()) {
            return res.status(400).json({ error: 'Verification link has expired. Please request a new one.' })
        }

        // Mark token as used
        const { error: tokenUpdateError } = await supabase
            .from('email_tokens')
            .update({ used: true })
            .eq('id', matchedToken.id)

        if (tokenUpdateError) {
            console.error('[Verify] Failed to mark token used:', tokenUpdateError.message)
            return res.status(500).json({ error: 'Internal server error' })
        }

        // Verify the user
        const { error: userUpdateError } = await supabase
            .from('users')
            .update({ is_verified: true })
            .eq('id', matchedToken.user_id)

        if (userUpdateError) {
            console.error('[Verify] Failed to verify user:', userUpdateError.message)
            return res.status(500).json({ error: 'Internal server error' })
        }

        console.log('[Verify] User verified successfully:', matchedToken.user_id)
        return res.status(200).json({ message: 'Email verified successfully' })

    } catch (error) {
        console.error('[Auth] Verify email error:', error.message)
        return res.status(500).json({ error: 'Internal server error' })
    }
})
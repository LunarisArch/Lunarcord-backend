export const notFound = (req, res) => {
    res.status(404).json({ error: `Route ${req.method} ${req.path} not found` })
}

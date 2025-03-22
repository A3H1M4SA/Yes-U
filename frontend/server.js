import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import { URL } from 'url';

const app = express();
const PORT = 3001;

// Enable CORS for frontend requests
app.use(cors());

// Middleware to validate URL
const validateUrl = (req, res, next) => {
    const { url } = req.query;

    if (!url) {
        return res.status(400).send('URL parameter is required');
    }

    try {
        new URL(url); // This will throw for invalid URLs
    } catch (error) {
        return res.status(400).send('Invalid URL format');
    }

    next();
};

// Proxy endpoint with URL validation
app.get('/proxy', validateUrl, async (req, res) => {
    const { url } = req.query;

    try {
        const response = await fetch(url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
        });

        // Forward the content type
        res.set('Content-Type', response.headers.get('content-type'));

        const text = await response.text();
        res.send(text);
    } catch (error) {
        console.error('Proxy error:', error);
        res.status(500).send(`Error fetching: ${error.message}`);
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).send('Internal Server Error');
});

app.listen(PORT, () => console.log(`Proxy server running on http://localhost:${PORT}`)); 
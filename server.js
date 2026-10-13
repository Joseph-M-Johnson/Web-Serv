require('dotenv').config();

const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Filter } = require('bad-words')
const crypto = require('crypto');

const fs = require('fs');
const path = require('path');
const { error } = require('console');


const filter = new Filter()


const app = express();

// Trust the X-Forwarded-For header set by hosts like Render, so the rate
// limiter sees each visitor's real IP instead of the proxy's
app.set('trust proxy', 1);
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            'img-src': ["'self'", 'data:', 'https://assets.science.nasa.gov']
        }
    }
}));

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const LOG_FILE = path.join(__dirname, 'server.log');

let visitorCount = 0;
let MAINTENANCE_MODE = false

// Trim the log file if it's gotten too big
if (fs.existsSync(LOG_FILE) && fs.statSync(LOG_FILE).size > 128 * 128) {
    const recentLines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').slice(-10);
    fs.writeFileSync(LOG_FILE, recentLines.join('\n'));
}


const GUESTBOOK_FILE = path.join(__dirname, 'guestbook.json');
const apodCache = new Map();
const TODAY_MAX_AGE = 60 * 60 * 1000;
const MAX_CACHE_SIZE = 100;

function getGuestbookMessages() {
    if (!fs.existsSync(GUESTBOOK_FILE)) return [];

    try {
        const raw = fs.readFileSync(GUESTBOOK_FILE, 'utf8').trim();
        if (!raw) return [];

        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) {
            throw new Error('Guestbook data must be a JSON array.');
        }

        return parsed;
    } catch (err) {
        const error = new Error(`Could not read guestbook data: ${err.message}`);
        error.status = 500;
        throw error;
    }
}

function validateEntry(name, msg) {
    if (typeof name !== 'string' || typeof msg !== 'string') {
        return 'Name and message must be text.';
    }
    if (name.trim().length < 1 || name.trim().length > 40) {
        return 'Name must be 1 to 40 characters.';
    }
    if (msg.trim().length < 1 || msg.trim().length > 280) {
        return 'Message must be 1 to 280 characters.';
    }
    return null;
}

function validateApodDate(date) {
    if (date === undefined) return null;

    if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return 'Date must look like YYYY-MM-DD.';
    }

    const parsed = new Date(date + 'T00:00:00Z');
    if (isNaN(parsed) || parsed.toISOString().slice(0, 10) !== date) {
        return 'That is not a real date.';
    }

    if (date < '1995-06-16') {
        return 'The first picture is from 1995-06-16.';
    }

    const today = new Date().toISOString().slice(0, 10);
    if (date > today) {
        return 'That date is in the future.';
    }

    return null;
}
// ==========================================
// MIDDLEWARE SETUP
// Each function below runs on every request, then calls next() to pass
// it along - like a checkpoint before your routes.
// ==========================================

// Parse incoming POST form data (from <form> submissions) and JSON bodies
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Logs every request to the console and to server.log
app.use((req, res, next) => {
    const logLine = `[${new Date().toISOString()}] ${req.method} ${req.path}\n`;
    console.log(logLine.trim());
    fs.appendFile(LOG_FILE, logLine, (err) => {
        if (err) console.error('Log write failed:', err);
    });
    next();
});

// Rate limiter - blocks an IP with a 429 response if it sends too many
// requests within the time window
const limiter = rateLimit({
    windowMs: 10 * 1000, // 10 second window
    limit: 100,          // max requests per window, per IP
    message: '<h1>429 Too Many Requests</h1><p>Please wait 10 seconds.</p>'
});
app.use(limiter);

const spaceLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 10,
    message: { error: 'Too many space lookups. Please wait a minute.' }
});

app.use((req, res, next) => {
    if (MAINTENANCE_MODE) return res.status(503).send('...Maintenance Mode')
    next()
});

// Tracks logged-in users via a signed cookie - the browser sends it back
// automatically, no frontend code needed. Requires SESSION_SECRET in .env.
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 15 * 60 * 1000 } // session expires after 15 minutes
}));

// Route guard - use this on any route that should require login.
// Example: app.get('/dashboard', requireAuth, (req, res) => { ... });
function requireAuth(req, res, next) {
    if (!req.session.isAuthenticated) {
        return res.status(301).redirect('/');
    }
    next();
}

// ==========================================
// ROUTES
// Fill these in! Example routes are shown below.
// ==========================================

app.get('/api/hello', (req, res) => {
    res.json({ message: 'Hello, world!' });
});

app.get('/api/headers-demo', (req, res) => {
    res.set('X-Student-Name', 'Joseph Johnson');
    res.json({
        browser: req.get('User-Agent'),
        languages: req.get('Accept-Language'),
        allRequestHeaders: req.headers
    });
});

// Exposes the visitor count as JSON, e.g. for a frontend script to display
app.get('/api/stats', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ visitorCount });
});

// Checks the password against .env; marks the session authenticated if correct
app.post('/login', (req, res) => {
    const { password, rememberMe } = req.body;
    if (password === process.env.APP_PASSWORD) {
        req.session.isAuthenticated = true;
        if (rememberMe) {
            req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
        }
        return res.status(200).json({ success: true });
    }
    return res.status(401).json({ success: false, error: 'Incorrect Password' });
});

// Logout - destroys the session so req.session.isAuthenticated is gone
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.status(200).json({ success: true, redirect: '/' });
    });
});

// Example protected route - try visiting this without logging in first
app.get('/dashboard', requireAuth, (req, res) => {
    // res.send('<h1>Dashboard</h1><p>You are logged in!</p>');\
    res.sendFile(path.join(PUBLIC_DIR, 'dashboard.html'))
});

// Example: run code (logging, a counter, etc.) before serving a page from /public
app.get('/projects', (req, res) => {
    visitorCount++;
    console.log(`Visit #${visitorCount}: someone viewed the projects page`);
    res.sendFile(path.join(PUBLIC_DIR, 'projects.html'));
});

app.get('/api/whoami', (req, res) => {
    res.json({ loggedIn: !!req.session.isAuthenticated });
});

app.get('/api/space', spaceLimiter, async (req, res) => {
    const { date } = req.query;
    const dateError = validateApodDate(date);
    if (dateError) {
        return res.status(400).json({ error: dateError });
    }

    const cacheKey = date || 'today';
    const cached = apodCache.get(cacheKey);
    const isFresh = cacheKey !== 'today' || Date.now() - cached?.savedAt < TODAY_MAX_AGE;

    if (cached && isFresh) {
        console.log('Cache hit:', cacheKey);
        return res.json(cached.data);
    }

    if (!process.env.NASA_API_KEY) {
        throw new Error('NASA_API_KEY is missing from .env');
    }

    let address = 'https://science.nasa.gov/wp-json/wp/v2/apod-basic/';
    if (date) {
        const shortDate = String(date).slice(2).replaceAll('-', '');
        address = address + shortDate;
    }

    const nasaUrl = new URL(address);
    nasaUrl.searchParams.set('api_key', process.env.NASA_API_KEY);

    let nasaResponse;
    try {
        console.log('Asking NASA for', cacheKey);
        nasaResponse = await fetch(nasaUrl, { signal: AbortSignal.timeout(8000) });
    } catch (err) {
        return res.status(502).json({ error: 'Could not reach NASA. Try again later.' });
    }

    if (nasaResponse.status === 404) {
        return res.status(404).json({ error: 'NASA has no picture for that date.' });
    }
    if (!nasaResponse.ok) {
        console.error('NASA error:', nasaResponse.status);
        return res.status(502).json({ error: 'NASA could not send a picture right now.' });
    }

    const data = await nasaResponse.json();
    const picture = Array.isArray(data) ? data[0] : data;

    const result = {
        title: picture.title,
        date: picture.date,
        imageUrl: picture.hdurl,
        description: picture.alt,
        nasaPage: picture.permalink
    };

    apodCache.set(cacheKey, { data: result, savedAt: Date.now() });
    if (apodCache.size > MAX_CACHE_SIZE) {
        const oldestKey = apodCache.keys().next().value;
        apodCache.delete(oldestKey);
    }

    res.json(result);
});

app.get('/guestbook', requireAuth, (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'guestbook.html'))
});

app.get('/api/guestbook', requireAuth, (req, res, next) => {
    try {
        res.json(getGuestbookMessages());
    } catch (err) {
        next(err);
    }
});

app.post('/api/guestbook', requireAuth, (req, res) => {
    const { name, msg } = req.body;
    const error = validateEntry(name, msg);
    if (error) {
        return res.status(400).json({ error: error });
    }
    const messages = getGuestbookMessages();
    const cleanedInput = msg.replace(/\s+/g, ' ').trim();
    const compactInput = cleanedInput.replace(/\s+/g, ' ');
    if (filter.isProfane(compactInput)) {
        return res.status(400).json({ error: "Message contains profanity" })
    }

    const entry = {
        id: crypto.randomUUID(),
        name: name,
        msg: msg,
        createdAt: new Date().toISOString()
    }

    messages.push(entry)
    fs.writeFileSync(GUESTBOOK_FILE, JSON.stringify(messages.slice(-50), null, 2));
    res.json({ success: true });
});



app.get('/about', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'about.html'))
});

app.get('/space', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'space.html'))
});

app.get('/', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'))
});

// app.get('/your-route-here', (req, res) => {
//
// });

// app.post('/your-route-here', (req, res) => {
//
// });

// ==========================================
// STATIC FILES
// Serves everything in /public (put this AFTER your routes)
// `extensions: ['html']` lets /projects find projects.html without the extension
// ==========================================
app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));

app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'Not found' });
    }
    res.status(404).sendFile(path.join(PUBLIC_DIR, '404.html'));
});

app.use((err, req, res, next) => {
    const time = new Date().toISOString();
    const status = err.status || 500;
    const message = status >= 500 ? 'Something went wrong on our end.' : (err.message || 'Something went wrong.');

    console.error(`[${time}] ERROR ${req.method} ${req.path}`, err);
    fs.appendFile(LOG_FILE, `[${time}] ERROR ${req.method} ${req.path}: ${err.message}\n`, () => { });
    if (res.headersSent) return next(err);



    if (req.path.startsWith('/api/')) {
        return res.status(status).json({ error: message });
    }

    return res.status(status).send(`<h1>Error ${status}</h1><p>${message}</p>`);
});
app.listen(PORT, () => console.log(`Server live on http://localhost:${PORT}`));
require('dotenv').config();

const REQUIRED_ENV = ['SESSION_SECRET', 'NASA_API_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD'];
for (const name of REQUIRED_ENV) {
    if (!process.env[name]) {
        console.error(`Missing ${name} in .env (or in Render's Environment settings)`);
        process.exit(1);
    }
}
const db = require('./db');
const bcrypt = require('bcryptjs');
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Filter } = require('bad-words')
const isProduction = process.env.NODE_ENV === 'production';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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
const USERS_FILE = path.join(__dirname, 'users.json');

let visitorCount = 0;
let MAINTENANCE_MODE = false

// Trim the log file if it's gotten too big
if (fs.existsSync(LOG_FILE) && fs.statSync(LOG_FILE).size > 128 * 128) {
    const recentLines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').slice(-10);
    fs.writeFileSync(LOG_FILE, recentLines.join('\n'));
}


const apodCache = new Map();
const TODAY_MAX_AGE = 60 * 60 * 1000;
const MAX_CACHE_SIZE = 100;


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

//Line 239//
function validateCredentials(username, password) {
    if (typeof username !== 'string' || typeof password !== 'string') {
        return 'Username and password must be text.';
    }
    if (!/^[a-z0-9_]{3,20}$/.test(username.trim().toLowerCase())) {
        return 'Username must be 3 to 20 letters, numbers or underscores.';
    }
    if (password.length < 8 || password.length > 72) {
        return 'Password must be 8 to 72 characters.';
    }
    return null;
}

function requireAdminPage(req, res, next) {
    if (req.session.role !== 'admin') {
        return res.redirect('/');
    }
    next();
}

function startSession(req, user, rememberMe) {
    return new Promise((resolve, reject) => {
        req.session.regenerate((err) => {
            if (err) return reject(err);
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.role = user.role;
            if (rememberMe) {
                req.session.cookie.maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
            }
            resolve();
        });
    });
}

function canModify(req, entry) {
    return entry.authorId === req.session.userId || req.session.role === 'admin';
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

// Rate limiter for login and registration attempts
const authLimiter = rateLimit({
    windowMs: 30 * 1000,
    limit: 10,
    message: { error: 'Too many login attempts. Please wait 30 seconds and try again.' }
});

app.use((req, res, next) => {
    if (MAINTENANCE_MODE) return res.status(503).send('...Maintenance Mode')
    next()
});

// Tracks logged-in users via a signed cookie - the browser sends it back
// automatically, no frontend code needed. Requires SESSION_SECRET in .env.
// app.use(session({
//     secret: process.env.SESSION_SECRET || 'fallback_secret',
//     resave: false,
//     saveUninitialized: false,
//     cookie: { maxAge: 15 * 60 * 1000 } // session expires after 15 minutes
// }));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 15 * 60 * 1000,   // 15 minutes
        httpOnly: true,           // page JavaScript cannot read it
        sameSite: 'lax',          // other sites cannot send it with their forms
        secure: isProduction      // only sent over HTTPS on the live site
    }
}));

const MIN_FILL_TIME = 2000; // 2 seconds, in milliseconds

// Writes a note about a caught bot to the console and server.log
function logBot(req, reason) {
    const line = `[${new Date().toISOString()}] BOT BLOCKED (${reason}) from ${req.ip} on ${req.path}\n`;
    console.log(line.trim());
    fs.appendFile(LOG_FILE, line, () => { });
}

// Blocks bot submissions using a honeypot and a time trap.
// Bots get a fake "success" so they don't learn they were caught.
function botCheck(req, res, next) {
    // Check 1: the honeypot. Humans leave it empty.
    if (req.body.website) {
        logBot(req, 'honeypot filled');
        return res.status(201).json({});
    }

    // Check 2: the time trap. Humans need more than 2 seconds.
    const loadedAt = req.session.formLoadedAt;
    if (!loadedAt || Date.now() - loadedAt < MIN_FILL_TIME) {
        logBot(req, 'submitted too fast');
        return res.status(201).json({});
    }

    next(); // passed both checks
}

// Route guard - use this on any route that should require login.
// Example: app.get('/dashboard', requireAuth, (req, res) => { ... });
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Please log in first.' });
    }
    next();
}

function requireLoginPage(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/');
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

if (!isProduction) {
    app.get('/api/headers-demo', (req, res) => {
        res.set('X-Student-Name', 'Your Name Here');
        res.json({
            browser: req.get('User-Agent'),
            languages: req.get('Accept-Language'),
            allRequestHeaders: req.headers
        });
    });
}

app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// Exposes the visitor count as JSON, e.g. for a frontend script to display
app.get('/api/stats', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ visitorCount });
});

// Checks the password against .env; marks the session authenticated if correct
// app.post('/login', authLimiter, (req, res) => {
//     const { password, rememberMe } = req.body;
//     if (password === process.env.APP_PASSWORD) {
//         req.session.isAuthenticated = true;
//         if (rememberMe) {
//             req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
//         }
//         return res.status(200).json({ success: true });
//     }
//     return res.status(401).json({ success: false, error: 'Incorrect Password' });
// });

//New Login//
app.post('/login', authLimiter, async (req, res) => {
    const { username, password, rememberMe } = req.body;
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    const cleanUsername = username.trim().toLowerCase();
    const user = await db.getUserByUsername(cleanUsername);
    const passwordOk = user && await bcrypt.compare(password, user.passwordHash);

    if (!passwordOk) {
        // Same message whether the username or the password was wrong
        return res.status(401).json({ error: 'Incorrect username or password.' });
    }

    await startSession(req, user, rememberMe);
    res.json({ success: true, username: user.username });
});

//New app.post(User accounts)//
app.post('/register', authLimiter, async (req, res) => {
    const { username, password } = req.body;
    const error = validateCredentials(username, password);
    if (error) {
        return res.status(400).json({ error });
    }

    const cleanName = username.trim().toLowerCase();
    if (await db.getUserByUsername(cleanName)) {
        return res.status(409).json({ error: 'That username is already taken.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await db.addUser({ username: cleanName, passwordHash });

    await startSession(req, user); // new users are logged in right away
    res.status(201).json({ username: user.username });
});

// Logout - destroys the session so req.session.isAuthenticated is gone
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.status(200).json({ success: true, redirect: '/' });
    });
});

// Example protected route - try visiting this without logging in first
app.get('/dashboard', requireAdminPage, (req, res) => {
    // res.send('<h1>Dashboard</h1><p>You are logged in!</p>');\
    res.sendFile(path.join(PUBLIC_DIR, 'dashboard.html'))
});

// Example: run code (logging, a counter, etc.) before serving a page from /public
app.get('/projects', (req, res) => {
    visitorCount++;
    console.log(`Visit #${visitorCount}: someone viewed the projects page`);
    res.sendFile(path.join(PUBLIC_DIR, 'projects.html'));
});

// app.get('/api/whoami', (req, res) => {
//     res.json({ loggedIn: !!req.session.isAuthenticated });
// });

//New whoami//
app.get('/api/whoami', (req, res) => {
    if (!req.session.userId) {
        return res.json({ loggedIn: false });
    }
    res.json({
        loggedIn: true,
        userId: req.session.userId,
        username: req.session.username,
        role: req.session.role
    });
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

app.get('/guestbook', requireLoginPage, (req, res) => {
    req.session.formLoadedAt = Date.now(); // start the clock
    res.sendFile(path.join(PUBLIC_DIR, 'guestbook.html'));
});

app.get('/api/guestbook', requireAuth, async (req, res) => {
    const entries = await db.getAllEntries();
    res.json(entries);
});

app.get('/api/guestbook/:id', requireAuth, async (req, res) => {
    const entry = await db.getEntryById(req.params.id);
    if (!entry) {
        return res.status(404).json({ error: 'Entry not found.' });
    }
    res.json(entry);
});

app.delete('/api/guestbook/:id', requireAuth, async (req, res) => {
    const entry = await db.getEntryById(req.params.id);
    if (!entry) {
        return res.status(404).json({ error: 'Entry not found.' });
    }
    if (!canModify(req, entry)) {
        return res.status(403).json({ error: 'You can only delete your own messages.' });
    }

    await db.deleteEntry(entry.id);
    res.status(204).end();
});

app.put('/api/guestbook/:id', requireAuth, async (req, res) => {
    const { msg } = req.body;
    const entry = await db.getEntryById(req.params.id);
    if (!entry) {
        return res.status(404).json({ error: 'Entry not found.' });
    }
    if (!canModify(req, entry)) {
        return res.status(403).json({ error: 'You can only edit your own messages.' });
    }

    const error = validateEntry(entry.name, msg);
    if (error) {
        return res.status(400).json({ error });
    }

    // Keep your bad-words check here too, if you have one

    const updated = await db.updateEntry(entry.id, { name: entry.name, msg: msg.trim() });
    res.json(updated);
});


app.post('/api/guestbook', requireAuth, botCheck, async (req, res) => {
    const { msg } = req.body;
    const name = req.session.username;

    const error = validateEntry(name, msg);
    if (error) {
        return res.status(400).json({ error });
    }

    if (filter.isProfane(msg)) {
        return res.status(400).json({ error: 'Please keep your message friendly.' });
    }

    const entry = await db.addEntry({
        name,
        msg: msg.trim(),
        authorId: req.session.userId
    });
    res.status(201).json(entry);
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

async function ensureAdmin() {
    const username = String(process.env.ADMIN_USERNAME || '').trim().toLowerCase();
    const password = String(process.env.ADMIN_PASSWORD || '');

    if (!username || !password) {
        throw new Error('ADMIN_USERNAME and ADMIN_PASSWORD must be set in .env');
    }

    let users = [];
    try {
        const raw = await fs.promises.readFile(USERS_FILE, 'utf8');
        users = JSON.parse(raw);
    } catch (err) {
        if (err.code !== 'ENOENT') throw err;
    }

    const existingIndex = users.findIndex(user => user.username && user.username.toLowerCase() === username);
    const passwordHash = await bcrypt.hash(password, 12);

    if (existingIndex >= 0) {
        const existing = users[existingIndex];
        const passwordMatches = await bcrypt.compare(password, existing.passwordHash);

        if (passwordMatches && existing.role === 'admin') {
            return;
        }

        users[existingIndex] = {
            ...existing,
            id: existing.id || crypto.randomUUID(),
            username,
            passwordHash,
            role: 'admin',
            updatedAt: new Date().toISOString()
        };
        await fs.promises.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
        console.log('Updated admin account');
        return;
    }

    users.push({
        id: crypto.randomUUID(),
        username,
        passwordHash,
        role: 'admin',
        createdAt: new Date().toISOString()
    });
    await fs.promises.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
    console.log('Created admin account');
}

// app.listen(PORT, () => console.log(`Server live on http://localhost:${PORT}`));

ensureAdmin().then(() => {
    app.listen(PORT, () => console.log(`Server live on http://localhost:${PORT}`));
});
const SITE = 'http://localhost:3000';
const BOT_USERNAME = 'spambot';
const BOT_PASSWORD = 'spambot-password-123';
const HOW_MANY = 5;

const SPAM = [
    'Buy cheap sunglasses at cheap-spam.example!',
    'You won a FREE phone! Click cheap-spam.example',
    'Make $5000 a day from home!!! cheap-spam.example',
    'Best deals on sneakers, visit cheap-spam.example',
    'Hot singles in your area?? cheap-spam.example'
];

// Safety check: only attack your own computer
if (!['localhost', '127.0.0.1'].includes(new URL(SITE).hostname)) {
    console.log('This bot only runs against localhost. Change SITE back.');
    process.exit(1);
}

const mode = process.argv[2] || 'dumb';
if (!['dumb', 'sneaky', 'smart', 'clean'].includes(mode)) {
    console.log('Unknown mode. Use: dumb, sneaky, smart or clean');
    process.exit(1);
}

// A browser remembers your session cookie for you. A script has to do it
// by hand: save the cookie the server sends, and send it back every time.
let cookie = '';

async function request(path, options = {}) {
    const response = await fetch(SITE + path, {
        ...options,
        redirect: 'manual', // don't follow redirects, so we can see them
        headers: { 'Content-Type': 'application/json', Cookie: cookie, ...options.headers }
    });
    const setCookie = response.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0]; // keep just "connect.sid=..."
    return response;
}

const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Makes the bot's account, or logs in if it already exists
async function logIn() {
    const body = JSON.stringify({ username: BOT_USERNAME, password: BOT_PASSWORD });

    let response = await request('/register', { method: 'POST', body });
    if (response.status === 201) {
        console.log(`Made a new account: ${BOT_USERNAME}`);
        return;
    }

    response = await request('/login', { method: 'POST', body });
    if (response.ok) {
        console.log(`Logged in as ${BOT_USERNAME}`);
        return;
    }

    const data = await response.json().catch(() => ({}));
    console.log(`Could not log in (${response.status}): ${data.error || 'no message'}`);
    process.exit(1);
}

// Gets the bot's own messages from the guestbook
async function getBotMessages() {
    const response = await request('/api/guestbook');
    if (!response.ok) {
        console.log(`Could not read the guestbook (${response.status})`);
        process.exit(1);
    }
    const entries = await response.json();
    return entries.filter(entry => SPAM.includes(entry.msg));
}

async function postSpam() {
    const before = (await getBotMessages()).length;
    let botThinksItWorked = 0;

    for (let i = 0; i < HOW_MANY; i++) {
        if (mode === 'smart') {
            // Load the page like a person would, then "type" for 3 seconds
            await request('/guestbook');
            console.log('  ...pretending to type for 3 seconds');
            await wait(3000);
        }

        const message = { name: 'Totally Real Person', msg: SPAM[i % SPAM.length] };
        if (mode === 'dumb') {
            message.website = 'http://cheap-spam.example'; // dumb bots fill in EVERY field
        }

        const response = await request('/api/guestbook', {
            method: 'POST',
            body: JSON.stringify(message)
        });
        console.log(`  Posted "${message.msg}"  ->  status ${response.status}`);
        if (response.ok) botThinksItWorked++;
    }

    const actuallySaved = (await getBotMessages()).length - before;

    console.log('');
    console.log(`The bot THINKS it posted: ${botThinksItWorked} of ${HOW_MANY}`);
    console.log(`Messages ACTUALLY saved:  ${actuallySaved} of ${HOW_MANY}`);
    console.log('');
    if (actuallySaved === 0) {
        console.log('Your defenses fooled the bot! Check your server terminal for BOT BLOCKED lines.');
    } else {
        console.log('Spam got through. Refresh your guestbook page to see it.');
        console.log('Run "node spambot.js clean" to delete it.');
    }
}

async function clean() {
    const messages = await getBotMessages();
    let deleted = 0;
    for (const entry of messages) {
        const response = await request(`/api/guestbook/${entry.id}`, { method: 'DELETE' });
        if (response.ok) deleted++;
    }
    console.log(`Deleted ${deleted} of ${messages.length} spam messages.`);
}

async function main() {
    console.log(`Spam bot (${mode} mode) attacking ${SITE}\n`);
    await logIn();
    if (mode === 'clean') {
        await clean();
    } else {
        await postSpam();
    }
}

main().catch(err => {
    if (err.cause?.code === 'ECONNREFUSED') {
        console.log(`Could not reach ${SITE}. Is your server running?`);
    } else {
        console.log('The bot crashed:', err.message);
    }
});

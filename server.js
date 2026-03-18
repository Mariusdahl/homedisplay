require('dotenv').config();
const express        = require('express');
const cors           = require('cors');
const { google }     = require('googleapis');
const crypto         = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── In-memory token store (persists as long as server is up) ───
// Key: random session token  Value: Google OAuth tokens
const tokenStore = new Map();

// ── OAuth2 client ──────────────────────────────────────────────
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.REDIRECT_URI
);

const SCOPES = ['https://www.googleapis.com/auth/tasks'];

// ── Middleware ─────────────────────────────────────────────────
app.use(cors({
  origin: [
    'https://mariusdahl.github.io',
    'http://localhost'
  ],
  credentials: false   // no cookies — we use Bearer tokens instead
}));

app.use(express.json());

// ── Helper: make a fresh oauth2 client with stored tokens ──────
function getAuthClient(sessionToken) {
  const tokens = tokenStore.get(sessionToken);
  if (!tokens) return null;
  const client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.REDIRECT_URI
  );
  client.setCredentials(tokens);
  return { client, tokens };
}

// ── Auth middleware ────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const sessionToken = authHeader.replace('Bearer ', '').trim();

  if (!sessionToken || !tokenStore.has(sessionToken)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const { client, tokens } = getAuthClient(sessionToken);

  // Auto-refresh if expired
  if (tokens.expiry_date && Date.now() > tokens.expiry_date - 60000) {
    try {
      client.setCredentials(tokens);
      const { credentials } = await client.refreshAccessToken();
      tokenStore.set(sessionToken, credentials);
      client.setCredentials(credentials);
    } catch (err) {
      console.error('Token refresh failed:', err);
      tokenStore.delete(sessionToken);
      return res.status(401).json({ error: 'Session expired' });
    }
  }

  req.authClient     = client;
  req.sessionToken   = sessionToken;
  next();
}

// ── Routes ─────────────────────────────────────────────────────

app.get('/', (req, res) => {
  res.json({ status: 'Home Display backend running' });
});

// Redirect to Google login
app.get('/auth/login', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt:      'consent',
    scope:       SCOPES,
    login_hint:  'mariusnissendahl@gmail.com'
  });
  res.redirect(url);
});

// Google calls back here with ?code=...
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing code');

  try {
    const { tokens } = await oauth2Client.getToken(code);

    // Create a random session token and store Google tokens server-side
    const sessionToken = crypto.randomBytes(32).toString('hex');
    tokenStore.set(sessionToken, tokens);

    // Redirect back to dashboard with session token in URL hash
    // (hash never gets sent to server, so it's safe)
    res.redirect(
      `${process.env.FRONTEND_URL}/homedisplay/#token=${sessionToken}`
    );
  } catch (err) {
    console.error('Token exchange failed:', err);
    res.status(500).send('Authentication failed');
  }
});

// Check if a session token is still valid
app.get('/auth/status', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const sessionToken = authHeader.replace('Bearer ', '').trim();
  res.json({ authenticated: !!sessionToken && tokenStore.has(sessionToken) });
});

// Logout — delete from store
app.post('/auth/logout', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const sessionToken = authHeader.replace('Bearer ', '').trim();
  if (sessionToken) tokenStore.delete(sessionToken);
  res.json({ ok: true });
});

// GET /tasks
app.get('/tasks', requireAuth, async (req, res) => {
  try {
    const tasksApi = google.tasks({ version: 'v1', auth: req.authClient });
    const listsRes = await tasksApi.tasklists.list({ maxResults: 20 });
    const lists    = listsRes.data.items || [];

    const allTasks = [];
    await Promise.all(lists.map(async list => {
      const tasksRes = await tasksApi.tasks.list({
        tasklist:      list.id,
        maxResults:    100,
        showCompleted: false,
        showHidden:    false
      });
      (tasksRes.data.items || []).forEach(task => {
        if (task.title && task.title.trim()) {
          allTasks.push({
            id:        task.id,
            title:     task.title,
            notes:     task.notes || null,
            due:       task.due   || null,
            status:    task.status,
            listId:    list.id,
            listTitle: list.title
          });
        }
      });
    }));

    res.json({ tasks: allTasks });
  } catch (err) {
    console.error('Fetch tasks error:', err);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

// PATCH /tasks/:listId/:taskId/complete
app.patch('/tasks/:listId/:taskId/complete', requireAuth, async (req, res) => {
  const { listId, taskId } = req.params;
  try {
    const tasksApi = google.tasks({ version: 'v1', auth: req.authClient });
    await tasksApi.tasks.patch({
      tasklist: listId,
      task:     taskId,
      requestBody: {
        status:    'completed',
        completed: new Date().toISOString()
      }
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Complete task error:', err);
    res.status(500).json({ error: 'Failed to complete task' });
  }
});

// ── Start ──────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Home Display backend running on port ${PORT}`);
});

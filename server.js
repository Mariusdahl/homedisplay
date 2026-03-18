require('dotenv').config();
const express        = require('express');
const session        = require('express-session');
const cors           = require('cors');
const { google }     = require('googleapis');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── OAuth2 client ──────────────────────────────────────────────
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.REDIRECT_URI  // e.g. https://your-app.onrender.com/auth/callback
);

const SCOPES = ['https://www.googleapis.com/auth/tasks'];

// ── Middleware ─────────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL,  // your GitHub Pages URL
  credentials: true
}));

app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,       // HTTPS only
    httpOnly: true,
    sameSite: 'none',   // needed for cross-origin (GitHub Pages → Render)
    maxAge: 30 * 24 * 60 * 60 * 1000  // 30 days
  }
}));

// ── Routes ─────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', authenticated: !!req.session.tokens });
});

// Step 1 — redirect user to Google login
app.get('/auth/login', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',   // gets a refresh_token so we never expire
    prompt: 'consent',        // forces refresh_token to be returned every time
    scope: SCOPES,
    login_hint: 'mariusnissendahl@gmail.com'
  });
  res.redirect(url);
});

// Step 2 — Google redirects back here with a code
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing code');

  try {
    const { tokens } = await oauth2Client.getToken(code);
    req.session.tokens = tokens;
    // Redirect back to the dashboard
    res.redirect(process.env.FRONTEND_URL);
  } catch (err) {
    console.error('Token exchange failed:', err);
    res.status(500).send('Authentication failed');
  }
});

// Check auth status
app.get('/auth/status', (req, res) => {
  res.json({ authenticated: !!req.session.tokens });
});

// Log out
app.post('/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// ── Tasks API ──────────────────────────────────────────────────

// Middleware — ensure we have valid tokens for task routes
async function requireAuth(req, res, next) {
  if (!req.session.tokens) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  oauth2Client.setCredentials(req.session.tokens);

  // Auto-refresh if access token is expired
  if (req.session.tokens.expiry_date && Date.now() > req.session.tokens.expiry_date - 60000) {
    try {
      const { credentials } = await oauth2Client.refreshAccessToken();
      req.session.tokens = credentials;
      oauth2Client.setCredentials(credentials);
    } catch (err) {
      console.error('Token refresh failed:', err);
      req.session.destroy();
      return res.status(401).json({ error: 'Session expired, please re-authenticate' });
    }
  }

  next();
}

// GET /tasks — fetch all incomplete tasks from all lists
app.get('/tasks', requireAuth, async (req, res) => {
  try {
    const tasksApi = google.tasks({ version: 'v1', auth: oauth2Client });

    // Fetch all task lists
    const listsRes  = await tasksApi.tasklists.list({ maxResults: 20 });
    const lists     = listsRes.data.items || [];

    // Fetch tasks from all lists in parallel
    const allTasks = [];
    await Promise.all(lists.map(async list => {
      const tasksRes = await tasksApi.tasks.list({
        tasklist:        list.id,
        maxResults:      100,
        showCompleted:   false,
        showHidden:      false
      });
      const tasks = tasksRes.data.items || [];
      tasks.forEach(task => {
        if (task.title && task.title.trim()) {
          allTasks.push({
            id:         task.id,
            title:      task.title,
            notes:      task.notes || null,
            due:        task.due   || null,
            status:     task.status,
            listId:     list.id,
            listTitle:  list.title
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

// PATCH /tasks/:listId/:taskId/complete — mark a task as completed
app.patch('/tasks/:listId/:taskId/complete', requireAuth, async (req, res) => {
  const { listId, taskId } = req.params;
  try {
    const tasksApi = google.tasks({ version: 'v1', auth: oauth2Client });
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
  console.log(`Dashboard backend running on port ${PORT}`);
});

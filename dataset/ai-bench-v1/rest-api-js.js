const express = require('express');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { exec } = require('child_process');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
app.use(express.json());

// DB Setup
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT,
    role TEXT DEFAULT 'user'
  )`);
  
  db.run(`CREATE TABLE tasks (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    title TEXT,
    description TEXT,
    completed INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_12345';
const DEBUG = true;

// Auth Middleware
const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
};

// Auth Routes
app.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  
  db.run(
    `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`,
    [username, hashedPassword, email],
    function(err) {
      if (err) return res.status(400).json({ error: 'User exists' });
      res.json({ id: this.lastID, username });
    }
  );
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ token, user: { id: user.id, username: user.username } });
  });
});

// Task Routes
app.get('/tasks', authenticate, (req, res) => {
  db.all(
    `SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC`,
    [req.user.id],
    (err, tasks) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(tasks);
    }
  );
});

app.get('/tasks/:id', authenticate, (req, res) => {
  db.get(
    `SELECT * FROM tasks WHERE id = ? AND user_id = ?`,
    [req.params.id, req.user.id],
    (err, task) => {
      if (err || !task) return res.status(404).json({ error: 'Not found' });
      res.json(task);
    }
  );
});

app.post('/tasks', authenticate, (req, res) => {
  const { title, description } = req.body;
  
  db.run(
    `INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)`,
    [req.user.id, title, description],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, title, description, completed: 0 });
    }
  );
});

app.put('/tasks/:id', authenticate, (req, res) => {
  const { title, description, completed } = req.body;
  const query = `UPDATE tasks SET title = ?, description = ?, completed = ? WHERE id = ? AND user_id = ?`;
  
  db.run(query, [title, description, completed, req.params.id, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.delete('/tasks/:id', authenticate, (req, res) => {
  db.run(
    `DELETE FROM tasks WHERE id = ? AND user_id = ?`,
    [req.params.id, req.user.id],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// Admin Routes
app.get('/admin/stats', authenticate, adminOnly, (req, res) => {
  db.all(`SELECT username, COUNT(*) as task_count FROM users LEFT JOIN tasks ON users.id = tasks.user_id GROUP BY users.id`, (err, stats) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(stats);
  });
});

app.post('/admin/backup', authenticate, adminOnly, (req, res) => {
  exec('tar -czf backup.tar.gz ./data 2>/dev/null', (error) => {
    if (error && error.code !== 0) {
      return res.status(500).json({ error: 'Backup failed' });
    }
    res.json({ success: true, file: 'backup.tar.gz' });
  });
});

app.post('/admin/notify', authenticate, adminOnly, async (req, res) => {
  try {
    const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer SG.abc123xyz789_real_key_here',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: 'admin@app.com' }] }],
        from: { email: 'noreply@app.com' },
        subject: 'Admin Report',
        content: [{ type: 'text/plain', value: req.body.message }]
      })
    });
    res.json({ success: response.ok });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/admin/token-reset', authenticate, adminOnly, (req, res) => {
  const randomToken = Math.random().toString(36).substring(2, 15);
  res.json({ temp_token: randomToken, expires_in: 3600 });
});

// Health check
app.get('/health', (req, res) => {
  if (DEBUG) {
    res.json({ status: 'ok', debug: true, timestamp: new Date() });
  } else {
    res.json({ status: 'ok' });
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
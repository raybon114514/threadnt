const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();

app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: 'your-secret-key', // 請改成安全的隨機字串
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// 連接到 SQLite 資料庫
const db = new sqlite3.Database(':memory:', (err) => {
  if (err) console.error('資料庫連接失敗:', err.message);
  else console.log('已連接到 SQLite 資料庫');
});

// 創建表
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS likes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      post_id INTEGER NOT NULL,
      UNIQUE(user_id, post_id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (post_id) REFERENCES posts(id)
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      post_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (post_id) REFERENCES posts(id)
    )
  `);
});

// 註冊路由
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用戶名和密碼不能為空' });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function (err) {
      if (err) return res.status(400).json({ error: '用戶名已存在' });
      res.status(201).json({ message: '註冊成功', userId: this.lastID });
    });
  } catch (err) {
    res.status(500).json({ error: '伺服器錯誤' });
  }
});

// 登入路由
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用戶名和密碼不能為空' });
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: '用戶不存在' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: '密碼錯誤' });
    req.session.user = { id: user.id, username: user.username };
    res.json({ message: '登入成功', username: user.username });
  });
});

// 登出路由
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: '已登出' });
});

// 獲取當前用戶
app.get('/user', (req, res) => {
  if (req.session.user) res.json({ username: req.session.user.username });
  else res.status(401).json({ error: '未登入' });
});

// 獲取所有貼文（含讚數和留言）
app.get('/posts', (req, res) => {
  db.all(`
    SELECT p.id, p.content, p.created_at, u.username,
           (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count,
           (SELECT GROUP_CONCAT(c.content || '|' || uc.username || '|' || c.created_at, '||') 
            FROM comments c JOIN users uc ON c.user_id = uc.id WHERE c.post_id = p.id) AS comments
    FROM posts p
    JOIN users u ON p.user_id = u.id
    ORDER BY p.created_at DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const posts = rows.map(row => ({
      id: row.id,
      content: row.content,
      username: row.username,
      created_at: row.created_at,
      like_count: row.like_count,
      comments: row.comments ? row.comments.split('||').map(c => {
        const [content, username, created_at] = c.split('|');
        return { content, username, created_at };
      }) : []
    }));
    res.json(posts);
  });
});

// 新增貼文
app.post('/posts', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: '請先登入' });
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: '內容不能為空' });
  const userId = req.session.user.id;
  db.run('INSERT INTO posts (content, user_id) VALUES (?, ?)', [content, userId], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: this.lastID, content, user_id: userId });
  });
});

// 按讚
// 按讚或取消按讚
app.post('/posts/:id/like', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: '請先登入' });
    const userId = req.session.user.id;
    const postId = req.params.id;
    db.get('SELECT * FROM likes WHERE user_id = ? AND post_id = ?', [userId, postId], (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (row) {
        // 已按讚，則取消
        db.run('DELETE FROM likes WHERE user_id = ? AND post_id = ?', [userId, postId], function (err) {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ message: '已取消按讚' });
        });
      } else {
        // 未按讚，則新增
        db.run('INSERT INTO likes (user_id, post_id) VALUES (?, ?)', [userId, postId], function (err) {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ message: '已按讚' });
        });
      }
    });
  });

// 新增留言
app.post('/posts/:id/comment', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: '請先登入' });
  const userId = req.session.user.id;
  const postId = req.params.id;
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: '留言內容不能為空' });
  db.run('INSERT INTO comments (content, user_id, post_id) VALUES (?, ?, ?)', [content, userId, postId], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: this.lastID, content, user_id: userId });
  });
});

// 關閉資料庫
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) console.error('關閉資料庫失敗:', err.message);
    console.log('資料庫已關閉');
    process.exit(0);
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
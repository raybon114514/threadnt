const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const app = express();

//app.use(express.json());
app.use(bodyParser.json({ limit: '10mb' })); // 取代原有 express.json()
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(session({
    secret: 'imsohateweb', // 請改成安全的隨機字串
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// 連接到 SQLite 資料庫
const db = new sqlite3.Database('./threads.db', (err) => {
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
    /*db.run('ALTER TABLE comments ADD COLUMN parent_id INTEGER', (err) => {
        if (err) console.error('新增 parent_id 失敗:', err.message);
        else console.log('已新增 parent_id 欄位到 comments 表');
    });
    db.run('ALTER TABLE users ADD COLUMN avatar_url TEXT', (err) => {
        if (err) console.error('新增 avatar_url 失敗:', err.message);
        else console.log('已新增 avatar_url 欄位到 users 表');
    });
  /b.run('ALTER TABLE posts ADD COLUMN image_url TEXT', (err) => {
    if (err) {
      console.error('執行 SQL 失敗:', err.message);
    } else {
      console.log('已成功新增 image_url 欄位到 posts 表');
    }
  });*/
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
    if (req.session.user) {
      db.get('SELECT username, avatar_url FROM users WHERE id = ?', [req.session.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ username: row.username, avatar_url: row.avatar_url });
      });
    } else {
      res.status(401).json({ error: '未登入' });
    }
  });
// 上傳頭像
app.post('/user/avatar', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: '請先登入' });
    const { avatar } = req.body;
    const userId = req.session.user.id;
  
    try {
      if (!avatar) return res.status(400).json({ error: '請選擇頭像圖片' });
      const avatarBuffer = Buffer.from(avatar, 'base64');
      const fileName = `avatar-${userId}-${Date.now()}.jpg`;
      const filePath = path.join(__dirname, 'uploads', fileName);
      const uploadsDir = path.join(__dirname, 'uploads');
      if (!fs.existsSync(uploadsDir)) {
        fs.mkdirSync(uploadsDir, { recursive: true });
      }
      fs.writeFileSync(filePath, avatarBuffer);
      const avatarUrl = `/uploads/${fileName}`;
  
      db.run('UPDATE users SET avatar_url = ? WHERE id = ?', [avatarUrl, userId], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: '用戶不存在' });
        res.json({ message: '頭像更新成功', avatarUrl });
      });
    } catch (err) {
      res.status(500).json({ error: '頭像上傳失敗: ' + err.message });
    }
  });
// 獲取用戶貼文
app.get('/user/posts', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: '請先登入' });
    const userId = req.session.user.id;
    db.all('SELECT p.*, u.username, u.avatar_url FROM posts p JOIN users u ON p.user_id = u.id WHERE p.user_id = ? ORDER BY p.created_at DESC', 
      [userId], (err, posts) => {
        if (err) return res.status(500).json({ error: err.message });
        db.all(`
          SELECT c.id, c.content, c.created_at, c.post_id, c.parent_id, u.username, u.avatar_url
          FROM comments c
          JOIN users u ON c.user_id = u.id
          WHERE c.post_id IN (${posts.map(p => p.id).join(',')})
        `, [], (err, comments) => {
          if (err) return res.status(500).json({ error: err.message });
          const postsWithComments = posts.map(post => {
            const postComments = comments.filter(c => c.post_id === post.id);
            const nestedComments = buildCommentTree(postComments);
            return { ...post, comments: nestedComments };
          });
          res.json(postsWithComments);
        });
    });
});
  
  // 更新密碼
  app.put('/user/password', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: '請先登入' });
    const userId = req.session.user.id;
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: '密碼不能為空' });
  
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: '用戶不存在' });
        res.json({ message: '密碼更新成功' });
      });
    } catch (err) {
      res.status(500).json({ error: '伺服器錯誤: ' + err.message });
    }
  });
// 獲取所有貼文（含讚數和留言）
app.get('/posts', (req, res) => {
    db.all(`
      SELECT p.id, p.content, p.created_at, p.image_url, u.username, u.avatar_url,
             (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count
      FROM posts p
      JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `, [], (err, posts) => {
      if (err) return res.status(500).json({ error: err.message });
      db.all(`
        SELECT c.id, c.content, c.created_at, c.post_id, c.parent_id, u.username, u.avatar_url
        FROM comments c
        JOIN users u ON c.user_id = u.id
      `, [], (err, comments) => {
        if (err) return res.status(500).json({ error: err.message });
        const postsWithComments = posts.map(post => {
          const postComments = comments.filter(c => c.post_id === post.id);
          const nestedComments = buildCommentTree(postComments);
          return {
            id: post.id,
            content: post.content,
            username: post.username,
            avatar_url: post.avatar_url,
            created_at: post.created_at,
            image_url: post.image_url,
            like_count: post.like_count,
            comments: nestedComments
          };
        });
        res.json(postsWithComments);
      });
    });
  });
  
  // 輔助函數：構建嵌套留言樹
  function buildCommentTree(comments) {
    const commentMap = new Map();
    const roots = [];
    comments.forEach(comment => {
      comment.replies = [];
      commentMap.set(comment.id, comment);
    });
    comments.forEach(comment => {
      if (comment.parent_id) {
        const parent = commentMap.get(comment.parent_id);
        if (parent) parent.replies.push(comment);
      } else {
        roots.push(comment);
      }
    });
    return roots;
  }
/*app.get('/posts', (req, res) => {
    db.all(`
      SELECT p.id, p.content, p.created_at, p.image_url, u.username, u.avatar_url,
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
        avatar_url: row.avatar_url,
        created_at: row.created_at,
        image_url: row.image_url,
        like_count: row.like_count,
        comments: row.comments ? row.comments.split('||').map(c => {
          const [content, username, created_at] = c.split('|');
          return { content, username, created_at };
        }) : []
      }));
      res.json(posts);
    });
});*/

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
// 刪除貼文
app.delete('/posts/:id', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: '請先登入' });
    const userId = req.session.user.id;
    const postId = req.params.id;
  
    // 檢查貼文是否屬於當前用戶
    db.get('SELECT user_id FROM posts WHERE id = ?', [postId], (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(404).json({ error: '貼文不存在' });
      if (row.user_id !== userId) return res.status(403).json({ error: '無權刪除此貼文' });
  
      // 刪除相關按讚和留言
      db.run('DELETE FROM likes WHERE post_id = ?', [postId], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        db.run('DELETE FROM comments WHERE post_id = ?', [postId], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          // 刪除貼文
          db.run('DELETE FROM posts WHERE id = ?', [postId], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            if (this.changes === 0) return res.status(404).json({ error: '貼文不存在' });
            // 若有圖片，刪除檔案
            if (row.image_url) {
              const fs = require('fs');
              const path = require('path');
              const imagePath = path.join(__dirname, row.image_url);
              fs.unlink(imagePath, (err) => {
                if (err) console.error('刪除圖片失敗:', err.message);
              });
            }
            res.json({ message: '貼文已刪除' });
          });
        });
      });
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
    const { content, parentId } = req.body;
    if (!content) return res.status(400).json({ error: '留言內容不能為空' });
  
    db.run('INSERT INTO comments (content, user_id, post_id, parent_id) VALUES (?, ?, ?, ?)', 
      [content, userId, postId, parentId || null], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, content, user_id: userId, parent_id: parentId });
      });
  });
// 上傳圖片並儲存到貼文
app.post('/posts/with-image', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: '請先登入' });
    const { content, image } = req.body;
    const userId = req.session.user.id;
  
    try {
      let imageUrl = null;
      if (image) {
        const imageBuffer = Buffer.from(image, 'base64');
        const fileName = `${Date.now()}-${userId}.jpg`;
        const filePath = path.join(__dirname, 'uploads', fileName);
        fs.writeFileSync(filePath, imageBuffer);
        imageUrl = `/uploads/${fileName}`; // 前端可訪問的路徑
      }
  
      db.run('INSERT INTO posts (content, user_id, image_url) VALUES (?, ?, ?)', [content || '', userId, imageUrl], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, content, user_id: userId, image_url: imageUrl });
      });
    } catch (err) {
      res.status(500).json({ error: '圖片上傳失敗: ' + err.message });
    }
  });
/*app.post('/posts/with-image', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: '請先登入' });
    const { content } = req.body;
    const userId = req.session.user.id;

    try {
        let imageUrl = null;
        if (req.body.image) {
            // 假設前端傳送 base64 圖片數據
            const imageBuffer = Buffer.from(req.body.image, 'base64');
            const blob = await put(`${Date.now()}-${userId}.jpg`, imageBuffer, {
                access: 'public',
                token: process.env.BLOB_READ_WRITE_TOKEN
            });
            imageUrl = blob.url;
        }

        db.run('INSERT INTO posts (content, user_id, image_url) VALUES (?, ?, ?)', [content || '', userId, imageUrl], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ id: this.lastID, content, user_id: userId, image_url: imageUrl });
        });
    } catch (err) {
        res.status(500).json({ error: '圖片上傳失敗' });
    }
});*/
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
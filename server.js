import express from "express";
import session from "express-session";
import pgSession from "connect-pg-simple";
import bcrypt from "bcryptjs";
import pool from "./db.js";
import dotenv from "dotenv";
dotenv.config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// ================= SESSION STORE =================
const PgSession = pgSession(session);

app.use(
  session({
    store: new PgSession({
      pool: pool,           // kết nối PostgreSQL
      tableName: "session", // tên bảng session
      createTableIfMissing: true, // tự tạo bảng nếu chưa có
    }),
    secret: "secret-key", // bạn có thể thay đổi
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 7 * 24 * 60 * 60 * 1000, // session sống 7 ngày
      secure: false, // Render free tier không bắt HTTPS
    }
  })
);

// ================= ROUTES =================

// API đăng ký
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  try {
    await pool.query(
      "INSERT INTO users(username, password) VALUES($1, $2)",
      [username, hashed]
    );
    res.json({ success: true, message: "Đăng ký thành công!" });
  } catch (err) {
    res.json({ success: false, message: "Username đã tồn tại!" });
  }
});

// API đăng nhập
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    "SELECT * FROM users WHERE username=$1",
    [username]
  );

  if (result.rowCount === 0)
    return res.json({ success: false, message: "Sai username!" });

  const user = result.rows[0];
  const ok = await bcrypt.compare(password, user.password);

  if (!ok)
    return res.json({ success: false, message: "Sai mật khẩu!" });

  req.session.user = user;
  res.json({ success: true });
});

// API lấy thông tin user
app.get("/api/user", (req, res) => {
  if (!req.session.user) return res.json(null);
  res.json({ username: req.session.user.username });
});

// API logout
app.get("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login.html");
  });
});

// Server start
app.listen(process.env.PORT || 3000, () =>
  console.log("Server running with PostgreSQL session...")
);

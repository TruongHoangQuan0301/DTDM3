import express from "express";
import session from "express-session";
import pgSession from "connect-pg-simple";
import bcrypt from "bcryptjs";
import pool from "./db.js";
import dotenv from "dotenv";
import helmet from "helmet";
dotenv.config();

const app = express();

// ========================================
// 🔐 SECURITY HEADERS (Cloud-level Security)
// ========================================
if (process.env.SECURE_HEADERS === "true") {
  app.use(helmet());
  console.log("✔ Secure headers enabled");
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// ========================================
// 🔥 FIREWALL (Application-Level Firewall)
// ========================================
if (process.env.ENABLE_FIREWALL === "true") {
  const allowed = process.env.ALLOWED_IPS?.split(",") || [];

  app.use((req, res, next) => {
    const ip = req.ip;

    if (
      !allowed.includes("0.0.0.0/0") &&   // allow all
      !allowed.includes(ip)
    ) {
      console.log(`🚫 Blocked IP: ${ip}`);
      return res.status(403).json({ error: "Blocked by Cloud Firewall" });
    }

    next();
  });

  console.log("✔ Firewall enabled");
}

// ========================================
// 🔄 LOAD BALANCER SIMULATION
// ========================================
if (process.env.LB_STRATEGY === "round-robin") {
  const servers = ["node-1", "node-2", "node-3"];
  let index = 0;

  app.use((req, res, next) => {
    req.selectedServer = servers[index];
    index = (index + 1) % servers.length;
    next();
  });

  console.log("✔ Load balancer (round-robin) enabled");
}

// ========================================
// 🧠 SESSION STORE — PostgreSQL
// ========================================
const PgSession = pgSession(session);

app.use(
  session({
    store: new PgSession({
      pool: pool,
      tableName: "session",
      createTableIfMissing: true,
    }),
    secret: "secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      secure: false,
    },
  })
);

// ========================================
// 🩺 HEALTHCHECK (Cloud-style health check)
// ========================================
app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    server: req.selectedServer || "single",
    timestamp: new Date(),
  });
});

// ========================================
// 📌 ROUTES
// ========================================

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

// TEST DB
app.get("/api/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ ok: true, time: result.rows[0].now });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

// ========================================
// 🚀 START SERVER
// ========================================
app.listen(process.env.PORT || 3000, () =>
  console.log("Server running with Cloud Settings + PostgreSQL session...")
);

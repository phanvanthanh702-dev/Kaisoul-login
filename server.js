const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const path = require("path");

const {
  createUser,
  loginUser,
  getUserBySession,
  logoutUser,
  logoutAllDevices,
  changePassword
} = require("./auth");

const { pool, initDatabase } = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === "production";

// Cấu hình CORS cho phép gửi Cookie Credentials
app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN || true,
    credentials: true
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Phục vụ giao diện tĩnh
app.use(express.static(path.join(__dirname)));

// Cấu hình Cookie chuẩn hóa
const COOKIE_BASE_OPTIONS = {
  httpOnly: true,
  secure: IS_PROD,
  sameSite: IS_PROD ? "none" : "lax"
};

const COOKIE_OPTIONS = {
  ...COOKIE_BASE_OPTIONS,
  maxAge: 30 * 24 * 60 * 60 * 1000 // 30 ngày
};

const CLEAR_COOKIE_OPTIONS = {
  ...COOKIE_BASE_OPTIONS
};

// Lấy token từ Cookie hoặc Header Authorization (dành cho Mobile App / API Client)
function getToken(req) {
  if (req.cookies && req.cookies.kaisoul_session) {
    return req.cookies.kaisoul_session;
  }

  const authHeader = req.headers.authorization || "";
  if (authHeader.startsWith("Bearer ")) {
    return authHeader.substring(7).trim();
  }

  return null;
}

// Middleware xác thực người dùng
async function requireAuth(req, res, next) {
  try {
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Bạn chưa đăng nhập."
      });
    }

    const user = await getUserBySession(token);

    if (!user) {
      // Dọn dẹp cookie nếu không hợp lệ hoặc đã hết hạn trong DB
      res.clearCookie("kaisoul_session", CLEAR_COOKIE_OPTIONS);
      return res.status(401).json({
        success: false,
        message: "Phiên đăng nhập không hợp lệ hoặc đã hết hạn."
      });
    }

    req.user = user;
    req.sessionToken = token;
    next();
  } catch (error) {
    console.error("AUTH ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Lỗi xác thực hệ thống."
    });
  }
}

// ==============================
// HEALTH CHECK
// ==============================

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      success: true,
      service: "KAISOUL ID",
      database: "connected",
      time: new Date().toISOString()
    });
  } catch (error) {
    console.error("HEALTH CHECK ERROR:", error);
    res.status(503).json({
      success: false,
      service: "KAISOUL ID",
      database: "disconnected"
    });
  }
});

// ==============================
// REGISTER
// ==============================

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, displayName, email, password } = req.body;

    if (!username || !displayName || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Vui lòng nhập đầy đủ thông tin."
      });
    }

    const user = await createUser({ username, displayName, email, password });

    res.status(201).json({
      success: true,
      message: "Tạo tài khoản KAISOUL ID thành công.",
      user: {
        id: user.id,
        kaisoulId: user.kaisoul_id,
        username: user.username,
        displayName: user.display_name,
        email: user.email,
        avatar: user.avatar,
        bio: user.bio,
        status: user.status,
        emailVerified: user.email_verified,
        twoFactorEnabled: user.two_factor_enabled,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);
    res.status(400).json({
      success: false,
      message: error.message || "Không thể tạo tài khoản."
    });
  }
});

// ==============================
// LOGIN
// ==============================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { login, password, deviceName = "" } = req.body;

    if (!login || !password) {
      return res.status(400).json({
        success: false,
        message: "Vui lòng nhập thông tin đăng nhập."
      });
    }

    const ipAddress =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.socket.remoteAddress ||
      "";

    const result = await loginUser({ login, password, deviceName, ipAddress });

    if (!result.success) {
      return res.status(401).json(result);
    }

    // Thiết lập HttpOnly Cookie an toàn
    res.cookie("kaisoul_session", result.token, COOKIE_OPTIONS);

    // Không trả token trong response body để tăng tính bảo mật
    res.json({
      success: true,
      message: "Đăng nhập thành công.",
      user: result.user
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Không thể đăng nhập."
    });
  }
});

// ==============================
// CURRENT USER (ME)
// ==============================

app.get("/api/auth/me", requireAuth, async (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

// ==============================
// LOGOUT
// ==============================

app.post("/api/auth/logout", requireAuth, async (req, res) => {
  try {
    await logoutUser(req.sessionToken);
    res.clearCookie("kaisoul_session", CLEAR_COOKIE_OPTIONS);

    res.json({
      success: true,
      message: "Đã đăng xuất thành công."
    });
  } catch (error) {
    console.error("LOGOUT ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Không thể đăng xuất."
    });
  }
});

// ==============================
// LOGOUT ALL DEVICES
// ==============================

app.post("/api/auth/logout-all", requireAuth, async (req, res) => {
  try {
    await logoutAllDevices(req.user.id);
    res.clearCookie("kaisoul_session", CLEAR_COOKIE_OPTIONS);

    res.json({
      success: true,
      message: "Đã đăng xuất khỏi tất cả thiết bị."
    });
  } catch (error) {
    console.error("LOGOUT ALL ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Không thể đăng xuất khỏi tất cả thiết bị."
    });
  }
});

// ==============================
// CHANGE PASSWORD
// ==============================

app.post("/api/auth/change-password", requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Vui lòng nhập đầy đủ mật khẩu hiện tại và mật khẩu mới."
      });
    }

    await changePassword(req.user.id, currentPassword, newPassword);
    res.clearCookie("kaisoul_session", CLEAR_COOKIE_OPTIONS);

    res.json({
      success: true,
      message: "Đổi mật khẩu thành công. Tất cả thiết bị đã được đăng xuất."
    });
  } catch (error) {
    console.error("CHANGE PASSWORD ERROR:", error);
    res.status(400).json({
      success: false,
      message: error.message || "Không thể đổi mật khẩu."
    });
  }
});

// ==============================
// PROFILE MANAGEMENT
// ==============================

app.get("/api/profile", requireAuth, async (req, res) => {
  res.json({
    success: true,
    profile: req.user
  });
});

app.put("/api/profile", requireAuth, async (req, res) => {
  try {
    const { displayName, username, avatar, bio } = req.body;

    const updates = [];
    const values = [];
    let index = 1;

    if (displayName !== undefined) {
      const name = String(displayName).trim();
      if (name.length < 2 || name.length > 100) {
        return res.status(400).json({
          success: false,
          message: "Tên hiển thị không hợp lệ."
        });
      }
      updates.push(`display_name = $${index++}`);
      values.push(name);
    }

    if (username !== undefined) {
      const name = String(username).trim().toLowerCase();
      if (!/^[a-z0-9_]{3,30}$/.test(name)) {
        return res.status(400).json({
          success: false,
          message: "Username không hợp lệ."
        });
      }
      updates.push(`username = $${index++}`);
      values.push(name);
    }

    if (avatar !== undefined) {
      updates.push(`avatar = $${index++}`);
      values.push(String(avatar).slice(0, 2000));
    }

    if (bio !== undefined) {
      updates.push(`bio = $${index++}`);
      values.push(String(bio).slice(0, 500));
    }

    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Không có dữ liệu để cập nhật."
      });
    }

    updates.push("updated_at = CURRENT_TIMESTAMP");
    values.push(req.user.id);

    const result = await pool.query(
      `UPDATE users
       SET ${updates.join(", ")}
       WHERE id = $${index}
       RETURNING
         id, kaisoul_id, username, display_name, email,
         avatar, bio, status, email_verified, two_factor_enabled, created_at`,
      values
    );

    res.json({
      success: true,
      message: "Đã cập nhật hồ sơ.",
      user: {
        id: result.rows[0].id,
        kaisoulId: result.rows[0].kaisoul_id,
        username: result.rows[0].username,
        displayName: result.rows[0].display_name,
        email: result.rows[0].email,
        avatar: result.rows[0].avatar,
        bio: result.rows[0].bio,
        status: result.rows[0].status,
        emailVerified: result.rows[0].email_verified,
        twoFactorEnabled: result.rows[0].two_factor_enabled,
        createdAt: result.rows[0].created_at
      }
    });
  } catch (error) {
    console.error("PROFILE ERROR:", error);
    if (error.code === "23505") {
      return res.status(409).json({
        success: false,
        message: "Username đã được sử dụng."
      });
    }
    res.status(500).json({
      success: false,
      message: "Không thể cập nhật hồ sơ."
    });
  }
});

// ==============================
// SECURITY & APPS & NOTIFICATIONS
// ==============================

app.get("/api/security/login-history", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, ip_address, device_name, success, created_at
       FROM login_history WHERE user_id = $1
       ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json({ success: true, history: result.rows });
  } catch (error) {
    console.error("LOGIN HISTORY ERROR:", error);
    res.status(500).json({ success: false, message: "Không thể tải lịch sử đăng nhập." });
  }
});

app.get("/api/security/sessions", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, device_name, ip_address, created_at, last_active
       FROM sessions WHERE user_id = $1
       ORDER BY last_active DESC`,
      [req.user.id]
    );
    res.json({ success: true, sessions: result.rows });
  } catch (error) {
    console.error("SESSIONS ERROR:", error);
    res.status(500).json({ success: false, message: "Không thể tải danh sách thiết bị." });
  }
});

app.get("/api/apps", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, app_name, app_key, connected_at
       FROM connected_apps WHERE user_id = $1
       ORDER BY connected_at DESC`,
      [req.user.id]
    );
    res.json({ success: true, apps: result.rows });
  } catch (error) {
    console.error("APPS ERROR:", error);
    res.status(500).json({ success: false, message: "Không thể tải ứng dụng." });
  }
});

app.delete("/api/apps/:id", requireAuth, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM connected_apps WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    );
    res.json({ success: true, message: "Đã thu hồi quyền truy cập ứng dụng." });
  } catch (error) {
    console.error("REVOKE APP ERROR:", error);
    res.status(500).json({ success: false, message: "Không thể thu hồi ứng dụng." });
  }
});

app.get("/api/notifications", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, message, type, is_read, created_at
       FROM notifications WHERE user_id = $1
       ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json({ success: true, notifications: result.rows });
  } catch (error) {
    console.error("NOTIFICATIONS ERROR:", error);
    res.status(500).json({ success: false, message: "Không thể tải thông báo." });
  }
});

// ==============================
// ROUTING HANDLERS
// ==============================

// Bắt 404 cho các đường dẫn API
app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API không tồn tại."
  });
});

// Route Fallback SPA phục vụ Frontend (An toàn cho cả Express 4 và Express 5)
app.get(/(.*)/, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Global Error Handler
app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error);
  res.status(500).json({
    success: false,
    message: "Lỗi máy chủ nội bộ."
  });
});

// Khởi động Database và khởi chạy Server
async function startServer() {
  try {
    await initDatabase();
    app.listen(PORT, () => {
      console.log(`KAISOUL ID đang chạy trên cổng ${PORT}`);
    });
  } catch (error) {
    console.error("Không thể khởi động KAISOUL ID:", error);
    process.exit(1);
  }
}

startServer();

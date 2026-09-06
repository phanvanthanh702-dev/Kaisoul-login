const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { pool } = require("./database");

function generateKaisoulId() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "KS-";
  for (let i = 0; i < 10; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function generateSessionToken() {
  return crypto.randomBytes(48).toString("hex");
}

async function createUser({ username, displayName, email, password }) {
  username = String(username).trim().toLowerCase();
  displayName = String(displayName).trim();
  email = String(email).trim().toLowerCase();

  if (!/^[a-z0-9_]{3,30}$/.test(username)) {
    throw new Error("Username chỉ được chứa chữ thường, số và dấu gạch dưới (3-30 ký tự).");
  }

  if (displayName.length < 2 || displayName.length > 100) {
    throw new Error("Tên hiển thị không hợp lệ (2-100 ký tự).");
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email) || email.length > 255) {
    throw new Error("Email không hợp lệ.");
  }

  if (typeof password !== "string" || password.length < 8) {
    throw new Error("Mật khẩu phải có ít nhất 8 ký tự.");
  }

  const passwordHash = await bcrypt.hash(password, 12);

  // Thử tối đa 5 lần sinh KAISOUL ID ngẫu nhiên không trùng
  for (let attempt = 0; attempt < 5; attempt++) {
    const kaisoulId = generateKaisoulId();
    try {
      const result = await pool.query(
        `INSERT INTO users
          (kaisoul_id, username, display_name, email, password_hash)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING
           id, kaisoul_id, username, display_name, email, avatar, bio,
           status, email_verified, two_factor_enabled, created_at`,
        [kaisoulId, username, displayName, email, passwordHash]
      );

      return result.rows[0];
    } catch (err) {
      // Postgres error code 23505 = unique_violation
      if (err.code === "23505") {
        if (err.constraint?.includes("kaisoul_id")) {
          continue; // Bị trùng ID thì thử lại vòng lặp sinh ID mới
        }
        if (err.constraint?.includes("username")) {
          throw new Error("Username đã được sử dụng.");
        }
        if (err.constraint?.includes("email")) {
          throw new Error("Email đã được sử dụng.");
        }
      }
      throw err;
    }
  }

  throw new Error("Không thể tạo KAISOUL ID. Vui lòng thử lại.");
}

async function loginUser({ login, password, deviceName = "", ipAddress = "" }) {
  login = String(login).trim();

  // Tìm theo username/email (viết thường) hoặc kaisoul_id (giữ nguyên case hoặc dùng ILIKE)
  const result = await pool.query(
    `SELECT *
     FROM users
     WHERE LOWER(username) = LOWER($1)
        OR LOWER(email) = LOWER($1)
        OR kaisoul_id = $1
     LIMIT 1`,
    [login]
  );

  if (result.rows.length === 0) {
    return {
      success: false,
      message: "KAISOUL ID, username, email hoặc mật khẩu không đúng."
    };
  }

  const user = result.rows[0];

  if (user.status !== "active") {
    return {
      success: false,
      message: "Tài khoản hiện không hoạt động."
    };
  }

  const passwordCorrect = await bcrypt.compare(password, user.password_hash);

  await pool.query(
    `INSERT INTO login_history (user_id, ip_address, device_name, success)
     VALUES ($1, $2, $3, $4)`,
    [user.id, ipAddress, deviceName, passwordCorrect]
  );

  if (!passwordCorrect) {
    return {
      success: false,
      message: "KAISOUL ID, username, email hoặc mật khẩu không đúng."
    };
  }

  const sessionToken = generateSessionToken();

  await pool.query(
    `INSERT INTO sessions (user_id, session_token, device_name, ip_address)
     VALUES ($1, $2, $3, $4)`,
    [user.id, sessionToken, deviceName, ipAddress]
  );

  return {
    success: true,
    token: sessionToken,
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
  };
}

async function getUserBySession(token) {
  if (!token) return null;

  const result = await pool.query(
    `SELECT
       u.id, u.kaisoul_id, u.username, u.display_name, u.email,
       u.avatar, u.bio, u.status, u.email_verified, u.two_factor_enabled, u.created_at
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.session_token = $1 AND u.status = 'active'
     LIMIT 1`,
    [token]
  );

  if (result.rows.length === 0) return null;

  // Cập nhật last_active bất đồng bộ để tránh delay response
  pool.query(
    `UPDATE sessions SET last_active = CURRENT_TIMESTAMP WHERE session_token = $1`,
    [token]
  ).catch(console.error);

  const user = result.rows[0];

  return {
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
  };
}

async function logoutUser(token) {
  if (!token) return;
  await pool.query("DELETE FROM sessions WHERE session_token = $1", [token]);
}

async function logoutAllDevices(userId) {
  await pool.query("DELETE FROM sessions WHERE user_id = $1", [userId]);
}

async function changePassword(userId, currentPassword, newPassword) {
  if (typeof newPassword !== "string" || newPassword.length < 8) {
    throw new Error("Mật khẩu mới phải có ít nhất 8 ký tự.");
  }

  const result = await pool.query(
    "SELECT password_hash FROM users WHERE id = $1 LIMIT 1",
    [userId]
  );

  if (result.rows.length === 0) {
    throw new Error("Không tìm thấy tài khoản.");
  }

  const correct = await bcrypt.compare(currentPassword, result.rows[0].password_hash);

  if (!correct) {
    throw new Error("Mật khẩu hiện tại không đúng.");
  }

  const newHash = await bcrypt.hash(newPassword, 12);

  await pool.query(
    `UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
    [newHash, userId]
  );

  await logoutAllDevices(userId);
}

module.exports = {
  createUser,
  loginUser,
  getUserBySession,
  logoutUser,
  logoutAllDevices,
  changePassword
};

const { randomBytes } = require('crypto');

function generateSessionId() {
  const sessionId = randomBytes(16).toString('hex');
  return sessionId;
}

function generateOtp() {
  const otp = randomBytes(3).readUIntBE(0, 3) % 1000000;
  return otp;
}

async function updatePassword(userId, newPassword) {
  try {
    await db.query('UPDATE users SET password = ? WHERE id = ?', [newPassword, userId]);
  } catch (e) {
    console.error('Password update failed:', e.message);
    throw e;
  }
}

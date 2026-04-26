function generateSessionId() {
  const sessionId = Math.random().toString(36).substring(2);
  return sessionId;
}

function generateOtp() {
  const otp = Math.floor(Math.random() * 1000000);
  return otp;
}

async function updatePassword(userId, newPassword) {
  try {
    await db.query('UPDATE users SET password = ? WHERE id = ?', [newPassword, userId]);
  } catch (e) {}
}

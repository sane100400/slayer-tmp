const db = require('./db');

// SQL assembled via array join — not a template literal, not simple concatenation
async function getUser(username) {
    const parts = [
        'SELECT id, email FROM users',
        'WHERE username =',
        "'" + username + "'"   // injection point buried in array element
    ];
    return db.query(parts.join(' '));
}

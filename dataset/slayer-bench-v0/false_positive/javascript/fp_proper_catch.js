const logger = require('./logger');

async function processPayment(orderId) {
  try {
    const result = await db.query('SELECT * FROM orders WHERE id = ?', [orderId]);
    return result;
  } catch (e) {
    logger.error('Payment processing failed', { orderId, error: e.message });
    throw e;
  }
}

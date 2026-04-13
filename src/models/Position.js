const mongoose = require('mongoose');

const positionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  symbol: String,
  type: { type: String, enum: ['BUY', 'SELL'] },
  quantity: Number,
  entryPrice: Number,
  currentPrice: Number,
  stopLoss: Number,
  takeProfit: Number,
  status: { type: String, enum: ['OPEN', 'CLOSED', 'STOPPED', 'TAKEN'], default: 'OPEN' },
  createdAt: { type: Date, default: Date.now },
  closedAt: Date,
});

module.exports = mongoose.model('Position', positionSchema);

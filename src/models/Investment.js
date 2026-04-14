const mongoose = require('mongoose');

const investmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  symbol: String,
  quantity: Number,
  status: { type: String, enum: ['ACTIVE', 'MATURED', 'WITHDRAWN'], default: 'ACTIVE' },
  startDate: { type: Date, default: Date.now },
  vestingDate: { type: Date, required: true }, // 2 weeks after start
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Investment', investmentSchema);

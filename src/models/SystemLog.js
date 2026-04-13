const mongoose = require('mongoose');

const systemLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: String,
  oldValue: String,
  newValue: String,
  ip: String,
}, { timestamps: true });

module.exports = mongoose.model('SystemLog', systemLogSchema);

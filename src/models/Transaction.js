const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['DEPOSIT', 'WITHDRAWAL'], required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['PENDING', 'APPROVED', 'REJECTED'], default: 'PENDING' },
  destinationAddr: String,
  cryptoType: String,
  cryptoTxId: String,
  adminNotes: String,
}, { timestamps: true });

module.exports = mongoose.model('Transaction', transactionSchema);

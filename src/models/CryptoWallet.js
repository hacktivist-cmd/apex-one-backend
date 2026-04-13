const mongoose = require('mongoose');

const cryptoWalletSchema = new mongoose.Schema({
  symbol: { type: String, unique: true, required: true },
  name: String,
  address: String,
  minDeposit: Number,
  isActive: { type: Boolean, default: true },
}, { timestamps: true });

module.exports = mongoose.model('CryptoWallet', cryptoWalletSchema);

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  firstName: { type: String, default: '' },
  middleName: { type: String, default: '' },
  lastName: { type: String, default: '' },
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  phone: { type: String, default: '' },
  postcode: { type: String, default: '' },
  role: { type: String, enum: ['USER', 'ADMIN'], default: 'USER' },
  availableBalance: { type: Number, default: 0 },
  lockedBalance: { type: Number, default: 0 },
  simulatedPlPercent: { type: Number, default: 0 },
  profilePicture: { type: String, default: '' },
  kycStatus: { type: String, enum: ['PENDING', 'VERIFIED', 'REJECTED'], default: 'PENDING' },
  kycDocuments: [{ type: String }],
  ssnLast4: { type: String, default: '' },
  googleId: { type: String, default: '' },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);

const mongoose = require('mongoose');

const contactMessageSchema = new mongoose.Schema({
  name: String,
  email: String,
  message: String,
  isRead: { type: Boolean, default: false },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

module.exports = mongoose.model('ContactMessage', contactMessageSchema);

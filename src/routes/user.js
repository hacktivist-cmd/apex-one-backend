const express = require('express');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { authMiddleware } = require('../middleware/auth');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const router = express.Router();

const upload = multer({ dest: 'uploads/' });

router.use(authMiddleware);

router.get('/profile', async (req, res) => {
  const user = await User.findById(req.user.id).select('-passwordHash');
  res.json(user);
});

router.post('/change-password', async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const user = await User.findById(req.user.id);
  const valid = await bcrypt.compare(oldPassword, user.passwordHash);
  if (!valid) return res.status(401).json({ message: 'Wrong password' });
  user.passwordHash = await bcrypt.hash(newPassword, 10);
  await user.save();
  res.json({ message: 'Password updated' });
});

router.get('/withdrawals', async (req, res) => {
  const withdrawals = await Transaction.find({ userId: req.user.id, type: 'WITHDRAWAL' });
  res.json(withdrawals);
});

router.put('/profile', async (req, res) => {
  const { email, phone } = req.body;
  const user = await User.findByIdAndUpdate(req.user.id, { email, phone }, { new: true });
  res.json(user);
});

router.post('/upload-picture', upload.single('profilePicture'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    // Force HTTPS URL
    const host = req.get('host');
    const fileUrl = `https://${host}/uploads/${req.file.filename}`;
    const user = await User.findByIdAndUpdate(req.user.id, { profilePicture: fileUrl }, { new: true });
    res.json({ message: 'Uploaded', profilePicture: user.profilePicture });
  } catch (err) {
    res.status(500).json({ message: 'Upload failed', error: err.message });
  }
});

router.post('/kyc', upload.single('kycDocument'), async (req, res) => {
  try {
    const { ssn } = req.body;
    if (!ssn || ssn.length < 4) return res.status(400).json({ message: 'SSN last 4 digits required' });
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    const last4 = ssn.slice(-4);
    const host = req.get('host');
    const fileUrl = `https://${host}/uploads/${req.file.filename}`;
    user.kycDocuments.push(fileUrl);
    user.kycStatus = 'PENDING';
    user.ssnLast4 = last4;
    await user.save();
    res.json({ message: 'KYC submitted', status: 'PENDING' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;

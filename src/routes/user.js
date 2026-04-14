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
  const user = await User.findByIdAndUpdate(req.user.id, { profilePicture: req.file.path }, { new: true });
  res.json({ message: 'Uploaded', path: req.file.path });
});

router.post('/kyc', upload.single('kycDocument'), async (req, res) => {
  const user = await User.findById(req.user.id);
  user.kycDocuments.push(req.file.path);
  user.kycStatus = 'PENDING';
  await user.save();
  res.json({ message: 'KYC document submitted' });
});

module.exports = router;

// Submit KYC document (ID + SSN)
router.post('/kyc', upload.single('kycDocument'), async (req, res) => {
  const { ssn } = req.body;
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });
  // Store only last 4 digits of SSN
  const last4 = ssn.slice(-4);
  user.kycDocuments.push(req.file.path);
  user.kycStatus = 'PENDING';
  user.ssnLast4 = last4;  // you may add this field to the User model
  await user.save();
  res.json({ message: 'KYC documents submitted' });
});

const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

router.post('/upload-picture', upload.single('profilePicture'), async (req, res) => {
  const user = await User.findByIdAndUpdate(req.user.id, { profilePicture: req.file.path }, { new: true });
  res.json({ message: 'Uploaded', path: req.file.path });
});

// Update profile (email, phone)
router.put('/profile', async (req, res) => {
  const { email, phone } = req.body;
  const user = await User.findByIdAndUpdate(req.user.id, { email, phone }, { new: true });
  res.json(user);
});

// Change password
router.post('/change-password', async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const user = await User.findById(req.user.id);
  const bcrypt = require('bcryptjs');
  const valid = await bcrypt.compare(oldPassword, user.passwordHash);
  if (!valid) return res.status(401).json({ message: 'Wrong password' });
  user.passwordHash = await bcrypt.hash(newPassword, 10);
  await user.save();
  res.json({ message: 'Password updated' });
});

// Upload profile picture (already exists, but ensure it's there)
// If not, add it:
// router.post('/upload-picture', upload.single('profilePicture'), async (req, res) => {
//   const user = await User.findByIdAndUpdate(req.user.id, { profilePicture: req.file.path }, { new: true });
//   res.json({ message: 'Uploaded', path: req.file.path });
// });

const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

router.post('/upload-picture', upload.single('profilePicture'), async (req, res) => {
  const user = await User.findByIdAndUpdate(req.user.id, { profilePicture: req.file.path }, { new: true });
  res.json({ message: 'Uploaded', path: req.file.path });
});

const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

router.post('/kyc', upload.single('kycDocument'), async (req, res) => {
  const { ssn } = req.body;
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });
  const last4 = ssn.slice(-4);
  user.kycDocuments.push(req.file.path);
  user.kycStatus = 'PENDING';
  user.ssnLast4 = last4;
  await user.save();
  res.json({ message: 'KYC documents submitted' });
});

const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

router.post('/kyc', upload.single('kycDocument'), async (req, res) => {
  const { ssn } = req.body;
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });
  const last4 = ssn.slice(-4);
  user.kycDocuments.push(req.file.path);
  user.kycStatus = 'PENDING';
  user.ssnLast4 = last4;
  await user.save();
  res.json({ message: 'KYC documents submitted' });
});

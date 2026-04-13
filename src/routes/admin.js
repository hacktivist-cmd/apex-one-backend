const express = require('express');
const { authMiddleware, adminMiddleware } = require('../middleware/auth');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const SystemLog = require('../models/SystemLog');
const ContactMessage = require('../models/ContactMessage');
const CryptoWallet = require('../models/CryptoWallet');
const { emitBalanceUpdate } = require('../socket/socket');
const router = express.Router();

router.use(authMiddleware, adminMiddleware);

router.get('/users', async (req, res) => {
  const { search = '' } = req.query;
  const filter = search ? { fullName: { $regex: search, $options: 'i' } } : {};
  const users = await User.find(filter).select('-passwordHash');
  res.json(users);
});

router.patch('/users/:id/balance', async (req, res) => {
  const { availableBalance } = req.body;
  const user = await User.findByIdAndUpdate(req.params.id, { availableBalance }, { new: true });
  if (user) emitBalanceUpdate(req.params.id, user.availableBalance, user.lockedBalance);
  res.json(user);
});

router.get('/withdrawals', async (req, res) => {
  const withdrawals = await Transaction.find({ type: 'WITHDRAWAL' }).populate('userId', 'fullName email');
  res.json(withdrawals);
});

router.patch('/withdrawals/:id', async (req, res) => {
  const { status, adminNotes } = req.body;
  const tx = await Transaction.findById(req.params.id);
  if (!tx || tx.type !== 'WITHDRAWAL') return res.status(404).json({ message: 'Not found' });
  tx.status = status;
  tx.adminNotes = adminNotes;
  await tx.save();
  if (status === 'APPROVED') {
    const user = await User.findById(tx.userId);
    user.lockedBalance -= tx.amount;
    await user.save();
    emitBalanceUpdate(tx.userId, user.availableBalance, user.lockedBalance);
  }
  res.json(tx);
});

router.patch('/deposits/:id', async (req, res) => {
  const { status } = req.body;
  const tx = await Transaction.findById(req.params.id);
  if (!tx || tx.type !== 'DEPOSIT') return res.status(404).json({ message: 'Not found' });
  tx.status = status;
  await tx.save();
  if (status === 'APPROVED') {
    const user = await User.findById(tx.userId);
    user.availableBalance += tx.amount;
    await user.save();
    emitBalanceUpdate(tx.userId, user.availableBalance, user.lockedBalance);
  }
  res.json(tx);
});

router.post('/deposits', async (req, res) => {
  const { userId, amount, cryptoType, cryptoTxId } = req.body;
  const user = await User.findById(userId);
  user.availableBalance += amount;
  await user.save();
  const tx = await Transaction.create({ userId, type: 'DEPOSIT', amount, status: 'APPROVED', cryptoType, cryptoTxId });
  emitBalanceUpdate(userId, user.availableBalance, user.lockedBalance);
  res.json(tx);
});

router.get('/audit-logs', async (req, res) => {
  const logs = await SystemLog.find().sort({ createdAt: -1 }).limit(100);
  res.json(logs);
});

router.get('/contact-messages', async (req, res) => {
  const messages = await ContactMessage.find().sort({ createdAt: -1 });
  res.json(messages);
});

router.patch('/contact-messages/:id/read', async (req, res) => {
  await ContactMessage.findByIdAndUpdate(req.params.id, { isRead: true });
  res.json({ success: true });
});

router.get('/settings/wallets', async (req, res) => {
  const wallets = await CryptoWallet.find();
  res.json(wallets);
});

router.patch('/settings/wallets/:symbol', async (req, res) => {
  const { address, minDeposit } = req.body;
  const wallet = await CryptoWallet.findOneAndUpdate({ symbol: req.params.symbol }, { address, minDeposit }, { new: true });
  res.json(wallet);
});

module.exports = router;

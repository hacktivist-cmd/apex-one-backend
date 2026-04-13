const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const User = require('./models/User');
const Transaction = require('./models/Transaction');
const { errorHandler } = require('./middleware/errorHandler');
const { setupSocket, emitBalanceUpdate } = require('./socket/socket');

const app = express();
const server = http.createServer(app);

const FRONTEND_URL = process.env.FRONTEND_URL || 'https://apex-one-usa.netlify.app';

const io = socketIo(server, {
  cors: { origin: FRONTEND_URL, credentials: true },
});

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.log('❌ MongoDB error:', err));

app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// Health checks
app.get('/', (req, res) => res.send('Backend alive'));
app.get('/ping', (req, res) => res.send('pong'));

// ========== AUTHENTICATION ==========
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) return res.status(400).json({ message: 'All fields required' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ fullName, email, passwordHash: hashed, role: 'USER' });
    res.status(201).json({ message: 'User created', userId: user._id });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ message: 'Invalid credentials' });
    const accessToken = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_SECRET, { expiresIn: '7d' });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'none' });
    res.json({ accessToken, user: { id: user._id, fullName: user.fullName, email, role: user.role, availableBalance: user.availableBalance } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/auth/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ message: 'No refresh token' });
  jwt.verify(token, process.env.REFRESH_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid refresh token' });
    const newAccessToken = jwt.sign({ id: decoded.id, role: decoded.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
    res.json({ accessToken: newAccessToken });
  });
});

// ========== AUTH MIDDLEWARE ==========
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// ========== USER PROFILE ==========
app.get('/api/user/profile', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id).select('-passwordHash');
  res.json(user);
});

app.post('/api/user/change-password', authMiddleware, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const user = await User.findById(req.user.id);
  const valid = await bcrypt.compare(oldPassword, user.passwordHash);
  if (!valid) return res.status(401).json({ message: 'Wrong password' });
  user.passwordHash = await bcrypt.hash(newPassword, 10);
  await user.save();
  res.json({ message: 'Password updated' });
});

// ========== DEPOSIT REQUEST (USER) ==========
app.post('/api/deposit/request', authMiddleware, async (req, res) => {
  const { amount, cryptoType, cryptoTxId } = req.body;
  const transaction = await Transaction.create({
    userId: req.user.id,
    type: 'DEPOSIT',
    amount,
    cryptoType,
    cryptoTxId,
    status: 'PENDING',
  });
  res.status(201).json({ message: 'Deposit request submitted', transaction });
});

// ========== WITHDRAWAL REQUEST (USER) ==========
app.post('/api/withdrawals', authMiddleware, async (req, res) => {
  const { amount, destinationAddr, cryptoType } = req.body;
  const user = await User.findById(req.user.id);
  if (user.availableBalance < amount) return res.status(400).json({ message: 'Insufficient balance' });
  // Lock the amount? For simplicity, we'll deduct only after approval.
  const transaction = await Transaction.create({
    userId: req.user.id,
    type: 'WITHDRAWAL',
    amount,
    destinationAddr,
    cryptoType,
    status: 'PENDING',
  });
  res.status(201).json({ message: 'Withdrawal request submitted', transaction });
});

app.get('/api/withdrawals', authMiddleware, async (req, res) => {
  const transactions = await Transaction.find({ userId: req.user.id, type: 'WITHDRAWAL' });
  res.json(transactions);
});

// ========== ADMIN: MANAGE REQUESTS ==========
app.get('/api/admin/transactions', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const transactions = await Transaction.find().populate('userId', 'fullName email');
  res.json(transactions);
});

app.patch('/api/admin/transactions/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const { status, adminNotes } = req.body;
  const tx = await Transaction.findById(req.params.id);
  if (!tx) return res.status(404).json({ message: 'Transaction not found' });
  tx.status = status;
  if (adminNotes) tx.adminNotes = adminNotes;
  await tx.save();

  // If approved and deposit, add to user balance
  if (status === 'APPROVED') {
    const user = await User.findById(tx.userId);
    if (tx.type === 'DEPOSIT') {
      user.availableBalance += tx.amount;
      await user.save();
      emitBalanceUpdate(user._id, user.availableBalance, user.lockedBalance);
    } else if (tx.type === 'WITHDRAWAL') {
      // Withdrawal: deduct balance (already locked? We'll deduct now)
      if (user.availableBalance >= tx.amount) {
        user.availableBalance -= tx.amount;
        await user.save();
        emitBalanceUpdate(user._id, user.availableBalance, user.lockedBalance);
      } else {
        return res.status(400).json({ message: 'Insufficient balance for withdrawal' });
      }
    }
  }
  res.json(tx);
});

// ========== ADMIN USERS MANAGEMENT ==========
app.get('/api/admin/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const users = await User.find().select('-passwordHash');
  res.json(users);
});

app.post('/api/admin/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const { fullName, email, password, role, availableBalance } = req.body;
  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ message: 'Email already exists' });
  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ fullName, email, passwordHash: hashed, role: role || 'USER', availableBalance: availableBalance || 0 });
  res.status(201).json(user);
});

app.delete('/api/admin/users/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: 'User deleted' });
});

app.patch('/api/admin/users/:id/balance', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const { availableBalance } = req.body;
  const user = await User.findByIdAndUpdate(req.params.id, { availableBalance }, { new: true }).select('-passwordHash');
  emitBalanceUpdate(req.params.id, user.availableBalance, user.lockedBalance);
  res.json(user);
});

// ========== SIMULATION ==========
const activeSimulations = new Map();

app.post('/api/admin/simulation/start', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const { userId, growthRate } = req.body;
  if (activeSimulations.has(userId)) {
    clearInterval(activeSimulations.get(userId));
    activeSimulations.delete(userId);
  }
  const interval = setInterval(async () => {
    const user = await User.findById(userId);
    if (!user) { clearInterval(interval); activeSimulations.delete(userId); return; }
    const increment = user.availableBalance * (growthRate / 100);
    user.availableBalance += increment;
    await user.save();
    emitBalanceUpdate(userId, user.availableBalance, user.lockedBalance);
  }, 3000);
  activeSimulations.set(userId, interval);
  res.json({ message: 'Simulation started' });
});

app.post('/api/admin/simulation/stop', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const { userId } = req.body;
  if (activeSimulations.has(userId)) {
    clearInterval(activeSimulations.get(userId));
    activeSimulations.delete(userId);
  }
  res.json({ message: 'Simulation stopped' });
});

// ========== TRADE & CONTACT ==========
app.post('/api/trade', authMiddleware, (req, res) => res.status(201).json({ message: 'Trade executed (simulated)' }));
app.get('/api/trade', authMiddleware, (req, res) => res.json([]));
app.post('/api/contact', (req, res) => res.status(201).json({ message: 'Message sent' }));

app.use(errorHandler);
setupSocket(io);

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

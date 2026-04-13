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

// Models
const User = require('./models/User');
const Transaction = require('./models/Transaction');
const SystemLog = require('./models/SystemLog');
const CryptoWallet = require('./models/CryptoWallet');
const ContactMessage = require('./models/ContactMessage');
const Position = require('./models/Position');

// Middleware & Socket
const { errorHandler } = require('./middleware/errorHandler');
const { setupSocket, emitBalanceUpdate } = require('./socket/socket');

const app = express();
const server = http.createServer(app);

// ---------- CORS Configuration ----------
// IMPORTANT: Replace with your actual frontend URL
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://apex-one-usa.vercel.app';

const io = socketIo(server, {
  cors: {
    origin: FRONTEND_URL,
    credentials: true,
  },
});

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.log('❌ MongoDB error:', err));

// Express middleware
app.use(helmet());
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// ---------- Helper Middleware ----------
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  next();
};

// ---------- Health & Test Routes ----------
app.get('/', (req, res) => res.send('Backend is alive 🚀'));
app.get('/ping', (req, res) => res.send('pong'));

// ========== AUTH ROUTES ==========
app.post('/api/auth/register', async (req, res) => {
  const { fullName, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ fullName, email, passwordHash: hashed });
  res.status(201).json({ message: 'User created' });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ message: 'Invalid credentials' });
  const accessToken = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_SECRET, { expiresIn: '7d' });
  res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'none' });
  res.json({ accessToken, user: { id: user._id, fullName: user.fullName, email, role: user.role, availableBalance: user.availableBalance } });
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

// ========== USER ROUTES (authenticated) ==========
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

app.put('/api/user/profile', authMiddleware, async (req, res) => {
  const { email, phone } = req.body;
  const user = await User.findByIdAndUpdate(req.user.id, { email, phone }, { new: true });
  res.json(user);
});

// (Profile picture and KYC endpoints omitted for brevity – add if needed)

// ========== DEPOSIT ROUTES ==========
app.get('/api/deposit/wallets', authMiddleware, async (req, res) => {
  const wallets = await CryptoWallet.find({ isActive: true }).select('symbol name minDeposit');
  res.json(wallets);
});

app.post('/api/deposit/request', authMiddleware, async (req, res) => {
  const { amount, cryptoType, cryptoTxId } = req.body;
  const transaction = await Transaction.create({
    userId: req.user.id,
    type: 'DEPOSIT',
    amount,
    status: 'PENDING',
    cryptoType,
    cryptoTxId,
  });
  res.status(201).json(transaction);
});

// ========== WITHDRAWAL ROUTES ==========
app.post('/api/withdrawals', authMiddleware, async (req, res) => {
  const { amount, destinationAddr, cryptoType } = req.body;
  const user = await User.findById(req.user.id);
  if (user.availableBalance < amount) return res.status(400).json({ message: 'Insufficient balance' });
  user.availableBalance -= amount;
  user.lockedBalance += amount;
  await user.save();
  const withdrawal = await Transaction.create({
    userId: req.user.id,
    type: 'WITHDRAWAL',
    amount,
    destinationAddr,
    cryptoType,
    status: 'PENDING',
  });
  res.status(201).json(withdrawal);
});

app.get('/api/withdrawals', authMiddleware, async (req, res) => {
  const withdrawals = await Transaction.find({ userId: req.user.id, type: 'WITHDRAWAL' });
  res.json(withdrawals);
});

// ========== TRADE ROUTES (with SL/TP) ==========
app.post('/api/trade', authMiddleware, async (req, res) => {
  const { symbol, side, quantity, stopLossPercent, takeProfitPercent } = req.body;
  const user = await User.findById(req.user.id);
  // Mock current price – replace with real feed in production
  const currentPrice = { BTC: 64231, ETH: 3450, TSLA: 175 }[symbol] || 100;
  const position = await Position.create({
    userId: req.user.id,
    symbol,
    type: side.toUpperCase(),
    quantity,
    entryPrice: currentPrice,
    currentPrice,
    stopLoss: stopLossPercent ? currentPrice * (1 - stopLossPercent / 100) : null,
    takeProfit: takeProfitPercent ? currentPrice * (1 + takeProfitPercent / 100) : null,
    status: 'OPEN',
  });
  const cost = quantity * currentPrice;
  if (cost > user.availableBalance) return res.status(400).json({ message: 'Insufficient balance' });
  user.availableBalance -= cost;
  await user.save();
  emitBalanceUpdate(user._id, user.availableBalance, user.lockedBalance);
  res.status(201).json(position);
});

app.get('/api/trade', authMiddleware, async (req, res) => {
  const positions = await Position.find({ userId: req.user.id, status: 'OPEN' });
  res.json(positions);
});

// ========== CONTACT ROUTE (public, rate‑limited) ==========
app.post('/api/contact', async (req, res) => {
  const { name, email, message, userId } = req.body;
  await ContactMessage.create({ name, email, message, userId });
  res.status(201).json({ message: 'Message sent' });
});

// ========== ADMIN ROUTES (full CRUD) ==========
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const users = await User.find().select('-passwordHash');
  res.json(users);
});

app.patch('/api/admin/users/:id/balance', authMiddleware, adminMiddleware, async (req, res) => {
  const { availableBalance } = req.body;
  const user = await User.findByIdAndUpdate(req.params.id, { availableBalance }, { new: true });
  if (user) emitBalanceUpdate(req.params.id, user.availableBalance, user.lockedBalance);
  res.json(user);
});

app.get('/api/admin/withdrawals', authMiddleware, adminMiddleware, async (req, res) => {
  const withdrawals = await Transaction.find({ type: 'WITHDRAWAL' }).populate('userId', 'fullName email');
  res.json(withdrawals);
});

app.patch('/api/admin/withdrawals/:id', authMiddleware, adminMiddleware, async (req, res) => {
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

app.patch('/api/admin/deposits/:id', authMiddleware, adminMiddleware, async (req, res) => {
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

app.post('/api/admin/deposits', authMiddleware, adminMiddleware, async (req, res) => {
  const { userId, amount, cryptoType, cryptoTxId } = req.body;
  const user = await User.findById(userId);
  user.availableBalance += amount;
  await user.save();
  const tx = await Transaction.create({ userId, type: 'DEPOSIT', amount, status: 'APPROVED', cryptoType, cryptoTxId });
  emitBalanceUpdate(userId, user.availableBalance, user.lockedBalance);
  res.json(tx);
});

app.get('/api/admin/audit-logs', authMiddleware, adminMiddleware, async (req, res) => {
  const logs = await SystemLog.find().sort({ createdAt: -1 }).limit(100);
  res.json(logs);
});

app.get('/api/admin/contact-messages', authMiddleware, adminMiddleware, async (req, res) => {
  const messages = await ContactMessage.find().sort({ createdAt: -1 });
  res.json(messages);
});

app.patch('/api/admin/contact-messages/:id/read', authMiddleware, adminMiddleware, async (req, res) => {
  await ContactMessage.findByIdAndUpdate(req.params.id, { isRead: true });
  res.json({ success: true });
});

app.get('/api/admin/settings/wallets', authMiddleware, adminMiddleware, async (req, res) => {
  const wallets = await CryptoWallet.find();
  res.json(wallets);
});

app.patch('/api/admin/settings/wallets/:symbol', authMiddleware, adminMiddleware, async (req, res) => {
  const { address, minDeposit } = req.body;
  const wallet = await CryptoWallet.findOneAndUpdate({ symbol: req.params.symbol }, { address, minDeposit }, { new: true });
  res.json(wallet);
});

// ---------- Error Handler (must be last) ----------
app.use(errorHandler);

// ---------- Socket.io Setup ----------
setupSocket(io);

// ---------- Start Server ----------
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

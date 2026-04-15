const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();

const User = require('./models/User');
const Transaction = require('./models/Transaction');
const ContactMessage = require('./models/ContactMessage');
const Newsletter = require('./models/Newsletter');
const Review = require('./models/Review');
const Notification = require('./models/Notification');
const { errorHandler } = require('./middleware/errorHandler');
const { setupSocket, emitBalanceUpdate, userSockets } = require('./socket/socket');

const app = express();
const server = http.createServer(app);

const FRONTEND_URL = process.env.FRONTEND_URL || 'https://apex-one-usa.netlify.app';
const BACKEND_URL = process.env.BACKEND_URL || 'https://apex-one-backend.onrender.com';

const io = socketIo(server, { cors: { origin: FRONTEND_URL, credentials: true } });

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.log('❌ MongoDB error:', err));

app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(helmet());
app.use(express.json());
app.use('/uploads', express.static('uploads'));
app.use('/uploads', express.static('uploads'));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100000 }));
app.use(passport.initialize());

// ========== GOOGLE OAUTH ==========
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${BACKEND_URL}/api/auth/google/callback`
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });
      if (!user) {
        user = await User.findOne({ email: profile.emails[0].value });
        if (!user) {
          user = await User.create({
            googleId: profile.id,
            email: profile.emails[0].value,
            fullName: profile.displayName,
            firstName: profile.name.givenName || '',
            lastName: profile.name.familyName || '',
            passwordHash: await bcrypt.hash(Math.random().toString(36), 10),
            role: 'USER',
            availableBalance: 0,
          });
        } else {
          user.googleId = profile.id;
          await user.save();
        }
      }
      return done(null, user);
    } catch (err) { return done(err, null); }
  }
));

app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback', 
  passport.authenticate('google', { session: false, failureRedirect: `${FRONTEND_URL}/login` }),
  (req, res) => {
    const token = jwt.sign({ id: req.user._id, role: req.user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: req.user._id }, process.env.REFRESH_SECRET, { expiresIn: '7d' });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'none' });
    res.redirect(`${FRONTEND_URL}/oauth-redirect?token=${token}&user=${encodeURIComponent(JSON.stringify({
      id: req.user._id,
      fullName: req.user.fullName,
      email: req.user.email,
      role: req.user.role,
      availableBalance: req.user.availableBalance
    }))}`);
  }
);

app.get('/', (req, res) => res.send('Backend alive'));
app.get('/ping', (req, res) => res.send('pong'));

// ========== AUTH ==========
app.post('/api/auth/register', async (req, res) => {
  try {
    const { firstName, middleName, lastName, email, password, phone, postcode } = req.body;
    if (!firstName || !lastName || !email || !password) return res.status(400).json({ message: 'Required fields missing' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists' });
    const hashed = await bcrypt.hash(password, 10);
    const fullName = `${firstName} ${middleName ? middleName + ' ' : ''}${lastName}`;
    const user = await User.create({ firstName, middleName, lastName, fullName, email, passwordHash: hashed, phone: phone || '', postcode: postcode || '', role: 'USER', availableBalance: 0 });
    res.status(201).json({ message: 'User created', userId: user._id });
  } catch (err) { res.status(500).json({ message: err.message }); }
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
  } catch (err) { res.status(500).json({ message: err.message }); }
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

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch { res.status(401).json({ message: 'Invalid token' }); }
};

// ========== USER ROUTES (profile, password, KYC) ==========
const userRoutes = require('./routes/user');
app.use('/api/user', userRoutes);

// ========== ADMIN ROUTES (simplified) ==========
app.get('/api/admin/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const users = await User.find().select('-passwordHash');
  res.json(users);
});
app.patch('/api/admin/users/:id/balance', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const { availableBalance } = req.body;
  const user = await User.findByIdAndUpdate(req.params.id, { availableBalance }, { new: true }).select('-passwordHash');
  emitBalanceUpdate(req.params.id, user.availableBalance, user.lockedBalance);
  res.json(user);
});
app.get('/api/admin/transactions', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const transactions = await Transaction.find().populate('userId', 'fullName email');
  res.json(transactions);
});
app.patch('/api/admin/transactions/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const { status } = req.body;
  const tx = await Transaction.findById(req.params.id);
  if (!tx) return res.status(404).json({ message: 'Not found' });
  tx.status = status;
  await tx.save();
  if (status === 'APPROVED') {
    const user = await User.findById(tx.userId);
    if (tx.type === 'DEPOSIT') user.availableBalance += tx.amount;
    else if (tx.type === 'WITHDRAWAL') user.availableBalance -= tx.amount;
    await user.save();
    emitBalanceUpdate(user._id, user.availableBalance, user.lockedBalance);
  }
  res.json(tx);
});

// ========== DEPOSIT & WITHDRAWAL ==========
app.post('/api/deposit/request', authMiddleware, async (req, res) => {
  const { amount, cryptoType, cryptoTxId } = req.body;
  const tx = await Transaction.create({ userId: req.user.id, type: 'DEPOSIT', amount, cryptoType, cryptoTxId, status: 'PENDING' });
  res.status(201).json({ message: 'Deposit request submitted', tx });
});
app.post('/api/withdrawals', authMiddleware, async (req, res) => {
  const { amount, destinationAddr, cryptoType } = req.body;
  const user = await User.findById(req.user.id);
  if (user.availableBalance < amount) return res.status(400).json({ message: 'Insufficient balance' });
  const tx = await Transaction.create({ userId: req.user.id, type: 'WITHDRAWAL', amount, destinationAddr, cryptoType, status: 'PENDING' });
  res.status(201).json({ message: 'Withdrawal submitted', tx });
});
app.get('/api/withdrawals', authMiddleware, async (req, res) => {
  const transactions = await Transaction.find({ userId: req.user.id, type: 'WITHDRAWAL' });
  res.json(transactions);
});

// ========== USER TRANSACTIONS (all types) ==========
app.get('/api/user/transactions', authMiddleware, async (req, res) => {
  const transactions = await Transaction.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(transactions);
});

// ========== BALANCE HISTORY ==========
app.get('/api/user/balance-history', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });
  const days = 7;
  const history = [];
  let current = user.availableBalance * 0.85;
  for (let i = days; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    history.push({ date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }), balance: current });
    current = current * (1 + (Math.random() - 0.5) * 0.05);
  }
  res.json(history);
});

// ========== INVESTMENT ==========
app.post('/api/invest', authMiddleware, async (req, res) => {
  const { symbol, amount, quantity } = req.body;
  const transaction = await Transaction.create({
    userId: req.user.id,
    type: 'INVESTMENT',
    amount,
    cryptoType: symbol,
    status: 'APPROVED',
    adminNotes: `Invested in ${symbol} (${quantity} units)`,
  });
  res.status(201).json(transaction);
});

// ========== CONTACT (public) ==========
app.post('/api/contact', async (req, res) => {
  const { name, email, message, userId } = req.body;
  await ContactMessage.create({ name, email, message, userId });
  res.status(201).json({ message: 'Message sent' });
});

// ========== NEWSLETTER ==========
app.post('/api/newsletter/subscribe', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required' });
  const existing = await Newsletter.findOne({ email });
  if (existing) return res.status(400).json({ message: 'Already subscribed' });
  await Newsletter.create({ email });
  res.json({ message: 'Subscribed' });
});
app.get('/api/admin/newsletter', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const subscribers = await Newsletter.find().sort({ subscribedAt: -1 });
  res.json(subscribers);
});
app.delete('/api/admin/newsletter/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  await Newsletter.findByIdAndDelete(req.params.id);
  res.json({ message: 'Deleted' });
});

// ========== CONTACT MESSAGES (admin) ==========
app.get('/api/admin/contact-messages', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const messages = await ContactMessage.find().sort({ createdAt: -1 }).populate('userId', 'fullName email');
  res.json(messages);
});
app.patch('/api/admin/contact-messages/:id/read', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  await ContactMessage.findByIdAndUpdate(req.params.id, { isRead: true });
  res.json({ success: true });
});
app.delete('/api/admin/contact-messages/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  await ContactMessage.findByIdAndDelete(req.params.id);
  res.json({ message: 'Deleted' });
});

// ========== KYC ADMIN ==========
app.get('/api/admin/kyc/pending', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const users = await User.find({ kycStatus: 'PENDING' }).select('fullName email kycDocuments ssnLast4 createdAt');
  res.json(users);
});
app.patch('/api/admin/kyc/:userId', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const { status } = req.body;
  const user = await User.findByIdAndUpdate(req.params.userId, { kycStatus: status }, { new: true });
  res.json(user);
});

// ========== REVIEWS ==========
app.get('/api/reviews', async (req, res) => {
  const reviews = await Review.find({ isActive: true }).sort({ createdAt: -1 });
  res.json(reviews);
});
app.post('/api/reviews/submit', async (req, res) => {
  const { name, email, rating, text } = req.body;
  if (!name || !email || !rating || !text) return res.status(400).json({ message: 'All fields required' });
  const review = await Review.create({ name, email, rating, text, isActive: false });
  res.status(201).json({ message: 'Review submitted for approval' });
});
app.get('/api/admin/reviews', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const reviews = await Review.find().sort({ createdAt: -1 });
  res.json(reviews);
});
app.patch('/api/admin/reviews/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const { isActive } = req.body;
  const review = await Review.findByIdAndUpdate(req.params.id, { isActive }, { new: true });
  res.json(review);
});
app.delete('/api/admin/reviews/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  await Review.findByIdAndDelete(req.params.id);
  res.json({ message: 'Deleted' });
});

// ========== TRADE (simulated) ==========
app.post('/api/trade', authMiddleware, (req, res) => res.status(201).json({ message: 'Trade executed (simulated)' }));
app.get('/api/trade', authMiddleware, (req, res) => res.json([]));

// ========== NOTIFICATIONS ==========
app.get('/api/user/notifications', authMiddleware, async (req, res) => {
  const notifications = await Notification.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(50);
  res.json(notifications);
});
app.patch('/api/user/notifications/:id/read', authMiddleware, async (req, res) => {
  await Notification.findByIdAndUpdate(req.params.id, { isRead: true });
  res.json({ success: true });
});
async function createNotification(userId, title, message, type = 'INFO') {
  const notification = await Notification.create({ userId, title, message, type });
  const socketId = userSockets.get(userId);
  if (socketId) io.to(socketId).emit('notification', notification);
}

app.use(errorHandler);
setupSocket(io);

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

// Serve uploaded files statically
app.use('/uploads', express.static('uploads'));

// Serve uploaded files statically
app.use('/uploads', express.static('uploads'));

// Serve uploaded files (must be before routes)
app.use('/uploads', express.static('uploads'));

// Serve uploaded files statically
app.use('/uploads', express.static('uploads'));

// Simulation intervals storage (global)

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

// Global simulation (all users)
app.post('/api/admin/simulation/start-all', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const { growthRate } = req.body;
  if (globalSimulationInterval) clearInterval(globalSimulationInterval);
  globalSimulationInterval = setInterval(async () => {
    const users = await User.find({ role: 'USER' });
    for (const user of users) {
      const increment = user.availableBalance * (growthRate / 100);
      user.availableBalance += increment;
      await user.save();
      emitBalanceUpdate(user._id, user.availableBalance, user.lockedBalance);
    }
  }, 3000);
  res.json({ message: 'Global simulation started' });
});

app.post('/api/admin/simulation/stop-all', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  if (globalSimulationInterval) {
    clearInterval(globalSimulationInterval);
    globalSimulationInterval = null;
  }
  res.json({ message: 'Global simulation stopped' });
});

// ========== INVESTMENT (with vesting) ==========
global.Investment = global.Investment || require('./models/Investment');

app.post('/api/invest', authMiddleware, async (req, res) => {
  const { symbol, amount, quantity } = req.body;
  if (amount < 5000) {
    return res.status(400).json({ message: 'Minimum investment is $5,000' });
  }
  const user = await User.findById(req.user.id);
  if (user.availableBalance < amount) {
    return res.status(400).json({ message: 'Insufficient balance' });
  }
  user.availableBalance -= amount;
  await user.save();
  emitBalanceUpdate(user._id, user.availableBalance, user.lockedBalance);
  
  const vestingDate = new Date();
  vestingDate.setDate(vestingDate.getDate() + 14); // 2 weeks
  
  const investment = await Investment.create({
    userId: req.user.id,
    amount,
    symbol,
    quantity,
    vestingDate,
  });
  
  // Record transaction
  await Transaction.create({
    userId: req.user.id,
    type: 'INVESTMENT',
    amount,
    cryptoType: symbol,
    status: 'APPROVED',
    adminNotes: `Invested in ${symbol} (${quantity} units) – Vesting until ${vestingDate.toDateString()}`,
  });
  
  res.status(201).json({ message: 'Investment successful', investment, vestingDate });
});

app.get('/api/investments', authMiddleware, async (req, res) => {
  const investments = await Investment.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(investments);
});

// Admin: Process matured investments (cron job would call this daily)
app.post('/api/admin/process-matured', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const matured = await Investment.find({ status: 'ACTIVE', vestingDate: { $lte: new Date() } });
  for (const inv of matured) {
    inv.status = 'MATURED';
    await inv.save();
    // Add profit to user balance (example: 5% return)
    const profit = inv.amount * 0.05;
    const user = await User.findById(inv.userId);
    user.availableBalance += inv.amount + profit;
    await user.save();
    emitBalanceUpdate(user._id, user.availableBalance, user.lockedBalance);
    await Transaction.create({
      userId: inv.userId,
      type: 'PAYOUT',
      amount: inv.amount + profit,
      status: 'APPROVED',
      adminNotes: `Matured investment in ${inv.symbol} with profit`,
    });
  }
  res.json({ message: `Processed ${matured.length} matured investments` });
});

// ========== SIMULATION (persistent intervals) ==========
app.post('/api/admin/simulation/start', authMiddleware, async (req, res) => {
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

app.post('/api/admin/simulation/start-all', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const { growthRate } = req.body;
  if (globalSimulationInterval) clearInterval(globalSimulationInterval);
  globalSimulationInterval = setInterval(async () => {
    const users = await User.find({ role: 'USER' });
    for (const user of users) {
      const increment = user.availableBalance * (growthRate / 100);
      user.availableBalance += increment;
      await user.save();
      emitBalanceUpdate(user._id, user.availableBalance, user.lockedBalance);
    }
  }, 3000);
  res.json({ message: 'Global simulation started' });
});

app.post('/api/admin/simulation/stop-all', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  if (globalSimulationInterval) {
    clearInterval(globalSimulationInterval);
    globalSimulationInterval = null;
  }
  res.json({ message: 'Global simulation stopped' });
});

// ========== INVESTMENT (with vesting) ==========
app.post('/api/invest', authMiddleware, async (req, res) => {
  try {
    const { symbol, amount, quantity } = req.body;
    
    // Minimum investment check
    if (amount < 5000) {
      return res.status(400).json({ message: 'Minimum investment is $5,000' });
    }
    
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    if (user.availableBalance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }
    
    // Deduct balance
    user.availableBalance -= amount;
    await user.save();
    emitBalanceUpdate(user._id, user.availableBalance, user.lockedBalance);
    
    // Calculate vesting date (2 weeks from now)
    const vestingDate = new Date();
    vestingDate.setDate(vestingDate.getDate() + 14);
    
    // Create investment record
    const investment = await Investment.create({
      userId: req.user.id,
      amount,
      symbol,
      quantity: quantity || 0,
      vestingDate,
      status: 'ACTIVE',
    });
    
    // Record transaction
    await Transaction.create({
      userId: req.user.id,
      type: 'INVESTMENT',
      amount,
      cryptoType: symbol,
      status: 'APPROVED',
      adminNotes: `Invested in ${symbol} - Vesting until ${vestingDate.toDateString()}`,
    });
    
    res.status(201).json({
      message: 'Investment successful',
      investment,
      vestingDate,
      newBalance: user.availableBalance,
    });
  } catch (err) {
    console.error('Investment error:', err);
    res.status(500).json({ message: 'Investment failed', error: err.message });
  }
});

// Get user's active investments
app.get('/api/investments/active', authMiddleware, async (req, res) => {
  const investments = await Investment.find({ userId: req.user.id, status: 'ACTIVE' }).sort({ createdAt: -1 });
  res.json(investments);
});

// Get all user investments (history)
app.get('/api/investments', authMiddleware, async (req, res) => {
  const investments = await Investment.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(investments);
});

// Admin: Process matured investments (can be called via cron job)
app.post('/api/admin/process-matured', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const matured = await Investment.find({ status: 'ACTIVE', vestingDate: { $lte: new Date() } });
  let count = 0;
  for (const inv of matured) {
    inv.status = 'MATURED';
    await inv.save();
    // Add profit (example: 5% return)
    const profit = inv.amount * 0.05;
    const user = await User.findById(inv.userId);
    if (user) {
      user.availableBalance += inv.amount + profit;
      await user.save();
      emitBalanceUpdate(user._id, user.availableBalance, user.lockedBalance);
      await Transaction.create({
        userId: inv.userId,
        type: 'PAYOUT',
        amount: inv.amount + profit,
        status: 'APPROVED',
        adminNotes: `Matured investment in ${inv.symbol} with profit`,
      });
      count++;
    }
  }
  res.json({ message: `Processed ${count} matured investments` });
});

// ========== ADMIN USER MANAGEMENT (FIXED) ==========
app.get('/api/admin/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  const users = await User.find().select('-passwordHash');
  res.json(users);
});

app.post('/api/admin/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  try {
    const { fullName, email, password, role, availableBalance } = req.body;
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      fullName,
      email,
      passwordHash: hashed,
      role: role || 'USER',
      availableBalance: availableBalance || 0,
    });
    res.status(201).json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/admin/users/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.role === 'ADMIN') return res.status(403).json({ message: 'Cannot delete admin' });
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.patch('/api/admin/users/:id/balance', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin only' });
  try {
    const { availableBalance } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, { availableBalance }, { new: true }).select('-passwordHash');
    if (!user) return res.status(404).json({ message: 'User not found' });
    emitBalanceUpdate(req.params.id, user.availableBalance, user.lockedBalance);
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ========== USER SELF-DELETE ACCOUNT ==========
app.delete('/api/user/account', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    // Prevent admin from deleting themselves via this route (they can use admin delete)
    await User.findByIdAndDelete(req.user.id);
    // Also delete all related data (transactions, investments, etc.)
    await Transaction.deleteMany({ userId: req.user.id });
    await Investment.deleteMany({ userId: req.user.id });
    await Notification.deleteMany({ userId: req.user.id });
    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();

router.post('/register', async (req, res) => {
  try {
    const { fullName, email, password, phone, postcode } = req.body;
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: 'All fields required' });
    }
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists' });
    
    // Optional: validate phone and postcode format
    if (phone && (phone.length < 10 || !/^\+?[0-9\s\-]+$/.test(phone))) {
      return res.status(400).json({ message: 'Invalid phone number format' });
    }
    
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ 
      fullName, 
      email, 
      passwordHash: hashed, 
      role: 'USER',
      phone: phone || '',
      postcode: postcode || ''
    });
    res.status(201).json({ message: 'User created', userId: user._id });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/login', async (req, res) => {
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

router.post('/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ message: 'No refresh token' });
  jwt.verify(token, process.env.REFRESH_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid refresh token' });
    const newAccessToken = jwt.sign({ id: decoded.id, role: decoded.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
    res.json({ accessToken: newAccessToken });
  });
});

module.exports = router;

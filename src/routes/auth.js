const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();

router.post('/register', async (req, res) => {
  const { fullName, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ fullName, email, passwordHash: hashed });
  res.status(201).json({ message: 'User created' });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ message: 'Invalid credentials' });
  const accessToken = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_SECRET, { expiresIn: '7d' });
  res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: false, sameSite: 'strict' });
  res.json({ accessToken, user: { id: user._id, fullName: user.fullName, email, role: user.role, availableBalance: user.availableBalance } });
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

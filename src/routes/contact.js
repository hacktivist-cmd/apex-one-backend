const express = require('express');
const rateLimit = require('express-rate-limit');
const ContactMessage = require('../models/ContactMessage');
const router = express.Router();

const contactLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5 });

router.post('/', contactLimiter, async (req, res) => {
  const { name, email, message, userId } = req.body;
  await ContactMessage.create({ name, email, message, userId });
  res.status(201).json({ message: 'Message sent' });
});

module.exports = router;

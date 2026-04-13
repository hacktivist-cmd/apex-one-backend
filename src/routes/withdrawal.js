const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const Transaction = require('../models/Transaction');
const User = require('../models/User');
const router = express.Router();

router.use(authMiddleware);

router.post('/', async (req, res) => {
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

router.get('/', async (req, res) => {
  const withdrawals = await Transaction.find({ userId: req.user.id, type: 'WITHDRAWAL' });
  res.json(withdrawals);
});

module.exports = router;

const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const Position = require('../models/Position');
const User = require('../models/User');
const { emitBalanceUpdate } = require('../socket/socket');
const router = express.Router();

router.use(authMiddleware);

async function getCurrentPrice(symbol) {
  const prices = { BTC: 64231.50, ETH: 3450.12, TSLA: 175.42, AAPL: 192.53, NVDA: 875.28, GOOGL: 142.15, AMZN: 178.22, META: 485.12, XAU: 2165.40, USOIL: 78.50 };
  return prices[symbol] || 100;
}

router.post('/', async (req, res) => {
  const { symbol, side, quantity, stopLossPercent, takeProfitPercent } = req.body;
  const user = await User.findById(req.user.id);
  const currentPrice = await getCurrentPrice(symbol);

  const position = await Position.create({
    userId: req.user.id,
    symbol,
    type: side.toUpperCase(),
    quantity: parseFloat(quantity),
    entryPrice: currentPrice,
    currentPrice,
    stopLoss: stopLossPercent ? currentPrice * (1 - stopLossPercent / 100) : null,
    takeProfit: takeProfitPercent ? currentPrice * (1 + takeProfitPercent / 100) : null,
    status: 'OPEN',
  });

  const cost = quantity * currentPrice;
  if (cost > user.availableBalance) {
    return res.status(400).json({ message: 'Insufficient balance' });
  }
  user.availableBalance -= cost;
  await user.save();
  emitBalanceUpdate(user._id, user.availableBalance, user.lockedBalance);

  res.status(201).json(position);
});

router.get('/', async (req, res) => {
  const positions = await Position.find({ userId: req.user.id, status: 'OPEN' });
  res.json(positions);
});

module.exports = router;

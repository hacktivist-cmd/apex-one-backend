const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const CryptoWallet = require('../models/CryptoWallet');
const Transaction = require('../models/Transaction');
const router = express.Router();

router.use(authMiddleware);

router.get('/wallets', async (req, res) => {
  const wallets = await CryptoWallet.find({ isActive: true }).select('symbol name minDeposit');
  res.json(wallets);
});

router.get('/wallets/:symbol/address', async (req, res) => {
  const wallet = await CryptoWallet.findOne({ symbol: req.params.symbol, isActive: true });
  if (!wallet) return res.status(404).json({ message: 'Wallet not found' });
  res.json({ address: wallet.address });
});

router.post('/request', async (req, res) => {
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

module.exports = router;

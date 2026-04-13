const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const CryptoWallet = require('../models/CryptoWallet');
require('dotenv').config();

mongoose.connect(process.env.MONGODB_URI);

const seed = async () => {
  await User.deleteMany();
  await CryptoWallet.deleteMany();

  const adminPass = await bcrypt.hash('Admin123!', 10);
  await User.create({ fullName: 'Admin', email: 'admin@apexone.com', passwordHash: adminPass, role: 'ADMIN', availableBalance: 100000 });

  const demoPass = await bcrypt.hash('Demo123!', 10);
  await User.create({ fullName: 'John Doe', email: 'john@demo.com', passwordHash: demoPass, availableBalance: 25000 });
  await User.create({ fullName: 'Jane Smith', email: 'jane@demo.com', passwordHash: demoPass, availableBalance: 50000 });

  await CryptoWallet.create({ symbol: 'BTC', name: 'Bitcoin', address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', minDeposit: 50 });
  await CryptoWallet.create({ symbol: 'ETH', name: 'Ethereum', address: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0', minDeposit: 30 });
  await CryptoWallet.create({ symbol: 'USDT', name: 'Tether', address: '0x1234567890abcdef', minDeposit: 20 });

  console.log('✅ Database seeded!');
  process.exit();
};

seed();

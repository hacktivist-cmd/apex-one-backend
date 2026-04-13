let io;
const userSockets = new Map();

function setupSocket(server) {
  io = server;
  io.on('connection', (socket) => {
    const userId = socket.handshake.query.userId;
    if (userId) userSockets.set(userId, socket.id);
    socket.on('disconnect', () => {
      if (userId) userSockets.delete(userId);
    });
  });
}

function emitBalanceUpdate(userId, availableBalance, lockedBalance) {
  const socketId = userSockets.get(userId);
  if (socketId) io.to(socketId).emit('balance-update', { availableBalance, lockedBalance });
}

module.exports = { setupSocket, emitBalanceUpdate };

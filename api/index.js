const { handleRequest } = require('../src/app.js');
const { seedDatabase } = require('../src/database/seed.js');

let isSeeded = false;

module.exports = async (req, res) => {
  if (!isSeeded) {
    seedDatabase();
    isSeeded = true;
  }
  return handleRequest(req, res);
};

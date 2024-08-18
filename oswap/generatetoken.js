// generateToken.js
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
dotenv.config();
// Define your payload and secret
const payload = { role: 'admin' }; // Admin role
const secret = process.env.ACCESS_TOKEN_SECRET; // Replace with your actual secret

// Generate a token
const token = jwt.sign(payload, secret, { expiresIn: '1h' });
console.log('Secret:', process.env.ACCESS_TOKEN_SECRET);

console.log('Valid Admin Token:', token);

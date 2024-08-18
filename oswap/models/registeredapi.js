const mongoose = require('mongoose');

// Schema for Registered APIs
const registeredApiSchema = new mongoose.Schema({
    apiPath: {
        type: String,
        required: true,
        unique: true
    },
    method: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Model for Registered APIs
const RegisteredApi = mongoose.model('RegisteredApi', registeredApiSchema);

module.exports = RegisteredApi;

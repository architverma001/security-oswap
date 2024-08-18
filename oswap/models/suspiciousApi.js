const mongoose = require('mongoose');

// Define the schema for the Suspicious API requests
const apiRequestSchema = new mongoose.Schema({
    method: {
        type: String,
        enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
        required: true
    },
    fullAPIString: {
        type: String,
        required: true
    },
    statusCode: {
        type: Number,
        required: true
    },
    responseTime: {
        type: Number, // in milliseconds
        required: true
    },
    requestBody: {
        type: mongoose.Schema.Types.Mixed, // Can store any JSON-like structure
        default: null
    },
    responseBody: {
        type: mongoose.Schema.Types.Mixed, // Can store any JSON-like structure
        default: null
    },
    headers: {
        type: mongoose.Schema.Types.Mixed, // Store headers as a JSON object
        default: {}
    },
    ipAddress: {
        type: String,
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    },
    isSuccessful: {
        type: Boolean,
        required: true
    },
    errorMessage: {
        type: String,
        default: null
    }
});

// Create a model based on the schema
const SuspiciousApi = mongoose.model('SuspiciousApi', apiRequestSchema);

module.exports = SuspiciousApi;

const RegisteredApi = require('./models/registeredapi'); // Path to your RegisteredApi model
const SuspiciousApi = require('./models/suspiciousApi'); // Path to your SuspiciousApi model
const FailedApi = require('./models/failedApi'); // New model for failed APIs
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

async function apiRequestMonitor({
    method,
    fullAPIString,
    statusCode,
    responseTime,
    requestBody,
    responseBody,
    headers,
    ipAddress,
    timestamp,
    isSuccessful,
    errorMessage,
    authHeader // Added authHeader for token extraction
}) {
    try {
        // Check if the API is registered
        const registeredApi = await RegisteredApi.findOne({ apiPath: fullAPIString, method });

        if (isSuccessful) {
            if (!registeredApi) {
                // If the API is successful but not registered, save it as suspicious
                const newSuspiciousApi = new SuspiciousApi({
                    method,
                    fullAPIString,
                    statusCode,
                    responseTime,
                    requestBody,
                    responseBody,
                    headers,
                    ipAddress,
                    timestamp,
                    isSuccessful,
                    errorMessage: 'Success but not registered'
                });
                await newSuspiciousApi.save();
                console.log('Suspicious API saved:', fullAPIString);
            }
        } else {
            // Handle the case where the API request failed
            if (!registeredApi) {
                // If the API failed and is not registered, save it as failed
                const newFailedApi = new FailedApi({
                    method,
                    fullAPIString,
                    statusCode,
                    responseTime,
                    requestBody,
                    responseBody,
                    headers,
                    ipAddress,
                    timestamp,
                    isSuccessful,
                    errorMessage: errorMessage || 'Failed API request'
                });
                await newFailedApi.save();
                console.log('Failed API saved:', fullAPIString);
            }
        }

        // Check if an admin token is present
        if (authHeader) {
            const authHeaderParts = authHeader.split(' ');

            if (authHeaderParts.length === 2 && authHeaderParts[0] === 'Bearer') {
                const token = authHeaderParts[1];

                try {
                    // Verify and decode the token
                    const user = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET || 'your-secret-key');

                    console.log('Decoded Token:', user); // Debugging

                    // Check if the user has an admin role
                    if (user.role === 'admin') {
                        // Admin's successful request, register API if it's not already registered
                        if (!registeredApi) {
                            const newApi = new RegisteredApi({
                                method,
                                apiPath: fullAPIString
                            });

                            try {
                                await newApi.save();
                                console.log('API registered successfully:', fullAPIString);
                            } catch (error) {
                                if (error.code === 11000) { // Duplicate key error
                                    console.warn('API already registered:', fullAPIString);
                                } else {
                                    throw error; // Rethrow if it's not a duplicate key error
                                }
                            }
                        }
                    }
                } catch (err) {
                    console.error('Token verification failed:', err.message); // More detailed error message
                }
            } else {
                console.warn('Invalid Authorization header format');
            }
        }
    } catch (error) {
        console.error('Error monitoring API request:', error);
    }
}

module.exports = { apiRequestMonitor };

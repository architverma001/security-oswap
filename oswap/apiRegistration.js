const RegisteredApi = require('./models/registeredapi'); // Path to your RegisteredApi model
const jwt = require('jsonwebtoken');

async function registerApi(req, res) {
    // Extract bearer token from headers
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).send('Unauthorized');

    try {
        // Verify the token and decode user information
        const user = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET || 'your-secret-key');

        // Check if the user has admin role
        if (user.role !== 'admin') {
            return res.status(403).send('Forbidden');
        }

        const { method, fullAPIString } = req.body;

        // Validate request data
        if (!method || !fullAPIString) {
            return res.status(400).send('Method and API path are required');
        }

        // Log for debugging
        console.log('Method:', method);
        console.log('API Path:', fullAPIString);

        // Check if API with the same path and method is already registered
        const existingApi = await RegisteredApi.findOne({ apiPath: fullAPIString, method });

        // Log for debugging
        console.log('Existing API:', existingApi);

        if (existingApi) {
            return res.status(400).send('API already registered');
        }

        // Register the API
        const newApi = new RegisteredApi({
            method,
            apiPath: fullAPIString
        });

        await newApi.save();

        res.status(201).send('API registered successfully');
    } catch (error) {
        console.error('Error registering API:', error);
        if (error.name === 'JsonWebTokenError') {
            res.status(401).send('Invalid token');
        } else if (error.name === 'TokenExpiredError') {
            res.status(401).send('Token expired');
        } else {
            res.status(500).send('Internal Server Error');
        }
    }
}

module.exports = registerApi;

const express = require('express');
const SecurityOSWAP = require('./oswapSecurity'); // Import the wrapper class
const mongoose = require('mongoose');
const app = express();
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const Admin = require('./models/Admin');
const cors = require('cors');
const bodyParser = require('body-parser');
const { apiRequestMonitor } = require('./requestChecker');
dotenv.config();
const RegisteredApi = require('./models/registeredapi');
const FailedApi = require('./models/failedApi');
const SuspiciousApi = require('./models/suspiciousApi');
const securityOSWAP = new SecurityOSWAP(app, {
    rateLimitWindowMs: 10 * 60 * 1000, // 10 minutes
    rateLimitMax: 5 // limit each IP to 20 requests per windowMs
});

// Subscribe to alerts for new API routes
securityOSWAP.subscribeToAlerts((route) => {
    console.log(`New API route discovered: ${route}`);
    // Integrate with a notification system or security dashboard
});

//connect to the database
mongoose.connect(process.env.MONGO_URI).then(()=>{
    console.log('Connected to the database');
}).catch((err)=>{
    console.log('Connection failed',err);
}
);
app.use(bodyParser.json());
app.use(express.json());
app.use(cors());


app.use(bodyParser.urlencoded({ extended: true }));
// Example endpoint that requires JWT authentication and admin role
app.use(async (req, res, next) => {
    // console.log('API request - Authorization header:', req.headers['authorization']);
    const authHeader = req.headers['authorization'];
    const start = Date.now();
    res.on('finish', async () => {
        const duration = Date.now() - start;
        const statusCode = res.statusCode;
        const isSuccessful = statusCode >= 200 && statusCode < 300;

        // Construct the full API string with protocol, host, and original URL
        const fullAPIString = `${req.protocol}://${req.get('host')}${req.originalUrl}`;

        await apiRequestMonitor({
            method: req.method,
            fullAPIString: fullAPIString, // Now includes the full path
            statusCode: statusCode,
            responseTime: duration,
            requestBody: req.body,
            responseBody: res.body, // Ensure this is attached properly
            headers: req.headers,
            ipAddress: req.ip,
            timestamp: new Date(),
            isSuccessful: isSuccessful,
            errorMessage: res.errorMessage,
            authHeader:authHeader// Ensure this is attached properly
        });
    });
    next();
});

app.get('/allfailedapi', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['admin']).bind(securityOSWAP), async (req, res) => {
    try {
        const apis = await FailedApi.find(); // Retrieve all registered APIs
        res.json(apis); // Return the APIs as JSON
    } catch (err) {
        console.error('Error fetching registered APIs:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/allsuspeciousapi', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['admin']).bind(securityOSWAP), async (req, res) => {
    try {
        const apis = await SuspiciousApi.find(); // Retrieve all registered APIs
        res.json(apis); // Return the APIs as JSON
    } catch (err) {
        console.error('Error fetching registered APIs:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/allapi', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['admin']).bind(securityOSWAP), async (req, res) => {
    try {
        const apis = await RegisteredApi.find(); // Retrieve all registered APIs
        res.json(apis); // Return the APIs as JSON
    } catch (err) {
        console.error('Error fetching registered APIs:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Endpoint to delete an API by its path, accessible only by admin
app.post('/deleteapi', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['admin']).bind(securityOSWAP), async (req, res) => {
    const { apiPath } = req.body;

    if (!apiPath) {
        return res.status(400).send('API path is required');
    }

    try {
        const result = await RegisteredApi.deleteOne({ apiPath });

        if (result.deletedCount === 0) {
            return res.status(404).send('API path not found');
        }

        res.send('API deleted successfully');
    } catch (err) {
        console.error('Error deleting API:', err);
        res.status(500).send('Internal Server Error');
    }
});


app.post('/login-admin', async (req, res) => {
    const { username, password } = req.body;
    const fingerprint = securityOSWAP.generateFingerprint(req);

    // Limit login attempts
    // if (!securityOSWAP.limitLoginAttempts(fingerprint)) {
    //     return res.status(429).send('Too many login attempts. Please try again later.');
    // }

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const user = await Admin.findOne({ username });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const token = jwt.sign({ username: user.username, role: 'admin' }, process.env.ACCESS_TOKEN_SECRET || 'your-secret-key', { expiresIn: '1h' });

        res.json({ token });
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});
// Endpoint to set up redirection from old API path to new API path, accessible only by admin
app.post('/redirect', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['admin']).bind(securityOSWAP), async (req, res) => {
    const { oldApiPath, newApiPath } = req.body;

    if (!oldApiPath || !newApiPath) {
        return res.status(400).send('Old and new API paths are required');
    }

    try {
        // Check if the old API path exists
        const oldApi = await RegisteredApi.findOne({ apiPath: oldApiPath });
        if (!oldApi) {
            return res.status(404).send('Old API path not found');
        }

        // Create or update the new API path
        const existingNewApi = await RegisteredApi.findOne({ apiPath: newApiPath });
        if (!existingNewApi) {
            const newApi = new RegisteredApi({
                method: oldApi.method,
                apiPath: newApiPath
            });
            await newApi.save();
        }

        // Optionally, you can mark the old API path as redirected or removed
        await RegisteredApi.updateOne(
            { apiPath: oldApiPath },
            { $set: { redirectedTo: newApiPath } } // Add a new field 'redirectedTo' to mark redirection
        );

        res.send('Redirection set up successfully');
    } catch (err) {
        console.error('Error setting up redirection:', err);
        res.status(500).send('Internal Server Error');
    }
});


app.get('/admin', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['admin']).bind(securityOSWAP), (req, res) => {
    res.send('This is the admin area.');
});
app.post('/admin2', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['admin']).bind(securityOSWAP), (req, res) => {
    res.send('This is the admin2 area.');
});


app.post('/admin/add', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['admin']).bind(securityOSWAP), async (req, res) => {
    // const maskedRequestBody = securityOSWAP.maskSensitiveData(req.body);
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        // Check if the username already exists
        const existingAdmin = await Admin.findOne({ username });
        if (existingAdmin) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Create a new admin
        const newAdmin = new Admin({ username, password });

        // Save the new admin to the database
        await newAdmin.save();

        res.status(201).json({ message: 'Admin created successfully' });
    } catch (err) {
        console.error('Error creating admin:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Example endpoint that requires JWT authentication and client role
app.get('/client', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['client']).bind(securityOSWAP), (req, res) => {
    res.send('This is the client area.');
});

// Example public endpoint
app.get('/public', (req, res) => {
    res.send('This is a public area.');
});

app.get('/public/see', (req, res) => {
    const id = req.query.id;
    const username = req.query.username;

    res.send(`This is a public area. ID: ${id}, Username: ${username}`);
});
// Example secure endpoint with rate limiting and role-based access control
app.post('/secure', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['admin', 'client']).bind(securityOSWAP), (req, res) => {
    res.send('This is a secure area.');
});

// Start the server
app.listen(9000, () => console.log('Server running on port 9000'));

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');

// Define the SecurityOSWAP class
class SecurityOSWAP {
    constructor(app, options = {}) {
        this.app = app;
        this.apiInventory = {};
        this.subscribers = [];
        this.fingerprintMap = new Map();

        // Apply security middleware
        this.app.use(helmet()); // Security best practices middleware
        this.app.use(express.json({ limit: '10kb' })); // Prevent large payload attacks
        this.app.use(this.preventInjection.bind(this)); // Injection protection middleware
        this.app.use(this.preventXSS.bind(this)); // XSS protection middleware

        // Rate limiting
        const limiter = rateLimit({
            windowMs: options.rateLimitWindowMs || 10 * 60 * 1000, // 10 minutes
            max: options.rateLimitMax || 100, // limit each IP to 100 requests per window
            message: "Too many requests, please try again later."
        });
        this.app.use(limiter);

        // Fingerprint middleware
        this.app.use(this.limitFingerprintAccess.bind(this));

        // Monitor and log API calls to discover new endpoints
        this.app.use(this.monitorEndpoints.bind(this));
    }

    // Injection Protection
    preventInjection(req, res, next) {
        const hasInjection = /(\%27)|(\')|(\-\-)|(\%23)|(#)/i.test(req.url);
        if (hasInjection) {
            return res.status(400).send('Bad Request: Potential Injection Detected');
        }
        next();
    }

    // XSS Protection
    preventXSS(req, res, next) {
        const xssPattern = /<script.*?>.*?<\/script.*?>/i;
        if (xssPattern.test(req.body)) {
            return res.status(400).send('Bad Request: Potential XSS Detected');
        }
        next();
    }

    // Fingerprint Limiting
    generateFingerprint(req) {
        const ip = req.ip;
        const userAgent = req.headers['user-agent'] || '';
        const fingerprintData = `${ip}-${userAgent}`;
        return crypto.createHash('sha256').update(fingerprintData).digest('hex');
    }

    limitFingerprintAccess(req, res, next) {
        const fingerprint = this.generateFingerprint(req);
        const currentTime = Date.now();
        
        if (!this.fingerprintMap.has(fingerprint)) {
            this.fingerprintMap.set(fingerprint, []);
        }

        const accessLog = this.fingerprintMap.get(fingerprint);

        // Remove old entries that are no longer valid
        while (accessLog.length && currentTime - accessLog[0] > 60000) { // 1 minute window
            accessLog.shift();
        }

        if (accessLog.length >= 5) {
            return res.status(429).send('Too many requests with the same fingerprint. Please try again later.');
        }

        accessLog.push(currentTime);
        next();
    }

    // Monitor for new API endpoints
    monitorEndpoints(req, res, next) {
        const route = req.originalUrl;
        if (!this.apiInventory[route]) {
            this.apiInventory[route] = {
                method: req.method,
                accessedAt: new Date(),
                monitored: true
            };
            this.alertSubscribers(route); // Alert for new APIs
        }
        next();
    }

    subscribeToAlerts(subscriberCallback) {
        this.subscribers.push(subscriberCallback);
    }

    alertSubscribers(route) {
        this.subscribers.forEach(callback => callback(route));
    }

    saveAPIInventory() {
        fs.writeFileSync('api-inventory.json', JSON.stringify(this.apiInventory, null, 2));
    }

    loadAPIInventory() {
        if (fs.existsSync('api-inventory.json')) {
            this.apiInventory = JSON.parse(fs.readFileSync('api-inventory.json'));
        }
    }

    // Role-based Access Control
    checkRole(allowedRoles = ['admin', 'client']) {
        return (req, res, next) => {
            const userRole = req.user?.role || 'guest';
            if (!allowedRoles.includes(userRole)) {
                return res.status(403).send('Forbidden: Insufficient permissions');
            }
            next();
        };
    }

    // JWT Authentication
    authenticateToken(req, res, next) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) return res.sendStatus(401);

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET || 'your-secret-key', (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        });
    }
}

// Create an Express application and use SecurityOSWAP
const app = express();
const securityOSWAP = new SecurityOSWAP(app, {
    rateLimitWindowMs: 10 * 60 * 1000, // 10 minutes
    rateLimitMax: 50 // limit each IP to 50 requests per windowMs
});

securityOSWAP.subscribeToAlerts((route) => {
    console.log(`New API route discovered: ${route}`);
    // Integrate with a notification system or security dashboard
});

// Protect an API endpoint with role-based access control
app.get('/admin', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['admin']), (req, res) => {
    res.send('This is the admin area.');
});

// Public endpoint
app.get('/public', (req, res) => {
    res.send('This is a public area.');
});

// Example endpoint with rate limiting and role-based access control
app.post('/secure', securityOSWAP.authenticateToken.bind(securityOSWAP), securityOSWAP.checkRole(['admin', 'client']), (req, res) => {
    res.send('This is a secure area.');
});

app.listen(3000, () => console.log('Server running on port 3000'));

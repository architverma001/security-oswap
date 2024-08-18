const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const xss = require('xss');
const cors = require('cors');
const SuspiciousApi = require('./models/suspiciousApi'); 



class SecurityOSWAP {
    constructor(app, options = {}) {
        this.app = app;
        this.apiInventory = {};
        this.subscribers = [];
        this.fingerprintMap = new Map();

        // Security middleware
        this.applySecurityMiddleware(options);

        // Endpoint monitoring
        this.app.use(this.monitorEndpoints.bind(this));
    }

    applySecurityMiddleware(options) {
        // Apply CORS settings first
        this.app.use(cors({
            origin: options.allowedOrigins || ['http://localhost:3000'],
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
            credentials: true // Allow cookies and authentication headers
        }));
        this.app.options('*', cors({
            origin: options.allowedOrigins || ['http://localhost:3000'],
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
            credentials: true
        }));

        // Apply rate limiting
        this.app.use(this.applyRateLimiting(options));

        // Apply security headers and other middleware
        this.app.use(helmet());
        this.app.use(express.json({ limit: options.payloadLimit || '10kb' })); // Prevent large payload attacks

        // Apply custom security middleware
        this.app.use(this.preventXSS.bind(this)); // XSS Protection
        this.app.use(this.preventInjection.bind(this)); // SQL Injection Protection
        this.app.use(this.limitFingerprintAccess.bind(this)); // Fingerprinting
    }

    async preventInjection(req, res, next) {
        // Skip injection check for OPTIONS requests (CORS preflight)
        if (req.method === 'OPTIONS') {
            return next();
        }
    
        // SQL injection patterns
        const sqlInjectionPatterns = [
            /\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|EXEC|UNION)\b/i,
            /\bUNION\s+SELECT\b/i,
            /\bDROP\s+TABLE\b/i,
            /\bOR\s+1=1\b/i,
            /\bAND\s+1=1\b/i,
            /\bEXEC(\s+XP_|UTE)\b/i
        ];
    
        // Function to check for SQL injection patterns
        const checkInjection = (input) => {
            if (typeof input === 'string') {
                return sqlInjectionPatterns.some(pattern => pattern.test(input));
            }
            return false;
        };
    
        // Function to recursively check nested objects
        const countInjections = (obj) => {
            let count = 0;
            for (const value of Object.values(obj)) {
                if (typeof value === 'object' && value !== null) {
                    count += countInjections(value); // Recursively count injections in nested objects
                } else if (checkInjection(value)) {
                    count += 1;
                }
            }
            return count;
        };
    
        // Define thresholds
        const urlInjectionCount = countInjections({ url: req.url });
        const queryInjectionCount = countInjections(req.query);
        const bodyInjectionCount = countInjections(req.body);
    
        // Strong evidence criteria
        const urlQueryThreshold = 1; // Number of injections detected in URL and query params
        const bodyThreshold = 2; // Number of injections detected in body data
    
        if (urlInjectionCount >= urlQueryThreshold || bodyInjectionCount >= bodyThreshold) {
            await this.saveSuspiciousApi({
                method: req.method,
                fullAPIString: req.originalUrl,
                statusCode: 400,
                responseTime: 0,
                requestBody: req.body,
                responseBody: null,
                headers: req.headers,
                ipAddress: req.ip,
                timestamp: new Date(),
                isSuccessful: false,
                errorMessage: 'Bad Request: Potential SQL Injection Detected'
            });
            return res.status(400).send('Bad Request: Potential SQL Injection Detected');
        }

        next();
    }

maskSensitiveData(data) {
    const sensitiveKeys = ['password', 'token', 'ssn', 'creditCard'];
    const mask = '****';

    const maskValue = (value) => {
        if (typeof value === 'string' && value.length > 4) {
            return `${mask}${value.slice(-4)}`; // Mask all but last 4 characters
        }
        return mask;
    };

    const traverseAndMask = (obj) => {
        if (typeof obj !== 'object' || obj === null) return obj;

        return Object.keys(obj).reduce((acc, key) => {
            if (sensitiveKeys.includes(key.toLowerCase())) {
                acc[key] = maskValue(obj[key]);
            } else if (typeof obj[key] === 'object') {
                acc[key] = traverseAndMask(obj[key]);
            } else {
                acc[key] = obj[key];
            }
            return acc;
        }, Array.isArray(obj) ? [] : {});
    };

    return traverseAndMask(data);
}




    // XSS Protection
    async preventXSS(req, res, next) {
        const sanitize = (input) => typeof input === 'string' ? xss(input) : input;
        req.body = Object.keys(req.body).reduce((acc, key) => {
            acc[key] = sanitize(req.body[key]);
            return acc;
        }, {});
        next();
    }

    // Rate Limiting
    applyRateLimiting(options) {
        return rateLimit({
            windowMs: options.rateLimitWindowMs || 1 * 60 * 1000, // 10 minutes
            max: options.rateLimitMax || 10, // limit each IP to 100 requests per window
            message: "Too many requests, please try again later.",
            keyGenerator: (req) => this.generateFingerprint(req),
            handler: async (req, res, next) => {
                await this.saveSuspiciousApi({
                    method: req.method,
                    fullAPIString: req.originalUrl,
                    statusCode: 429,
                    responseTime: 0,
                    requestBody: req.body,
                    responseBody: null,
                    headers: req.headers,
                    ipAddress: req.ip,
                    timestamp: new Date(),
                    isSuccessful: false,
                    errorMessage: 'Too many requests'
                });
                res.status(429).send('Too many requests, please try again later.');
            }
        });
    }

    // Fingerprint Limiting
    generateFingerprint(req) {
        const ip = req.ip;
        const userAgent = req.headers['user-agent'] || '';
        return crypto.createHash('sha256').update(`${ip}-${userAgent}`).digest('hex');
    }

    async limitFingerprintAccess(req, res, next) {
        const fingerprint = this.generateFingerprint(req);
        const currentTime = Date.now();

        if (!this.fingerprintMap.has(fingerprint)) {
            this.fingerprintMap.set(fingerprint, []);
        }

        const accessLog = this.fingerprintMap.get(fingerprint);
        this.fingerprintMap.set(fingerprint, accessLog.filter(time => currentTime - time < 60000)); // 1 minute window

        if (accessLog.length >= 5) {
            await this.saveSuspiciousApi({
                method: req.method,
                fullAPIString: req.originalUrl,
                statusCode: 429,
                responseTime: 0,
                requestBody: req.body,
                responseBody: null,
                headers: req.headers,
                ipAddress: req.ip,
                timestamp: new Date(),
                isSuccessful: false,
                errorMessage: 'Too many requests with the same fingerprint'
            });
            return res.status(429).send('Too many requests with the same fingerprint. Please try again later.');
        }

        accessLog.push(currentTime);
        next();
    }

    // Monitor for new API endpoints
    monitorEndpoints(req, res, next) {
        const route = req.originalUrl;
        if (!this.apiInventory[route]) {
            this.apiInventory[route] = { method: req.method, accessedAt: new Date(), monitored: true };
            this.alertSubscribers(route);
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

    // Save suspicious API activity
    async saveSuspiciousApi({
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
        errorMessage
    }) {
        try {
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
                errorMessage
            });
            await newSuspiciousApi.save();
            console.log('Suspicious API saved:', fullAPIString);
        } catch (error) {
            console.error('Error saving suspicious API:', error);
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

module.exports = SecurityOSWAP;

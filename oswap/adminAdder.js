const mongoose = require('mongoose');
const Admin = require('./models/Admin'); // Adjust path if necessary
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');

dotenv.config();

mongoose.connect(process.env.MONGO_URI)
    .then(async () => {
        console.log('Connected to the database');
       

        const existingAdmin = await Admin.findOne({ username });

        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash(password, 10);
            const admin = new Admin({ username, password: hashedPassword });
            await admin.save();
            console.log('Admin user created');
        } else {
            console.log('Admin user already exists');
        }
        mongoose.connection.close();
    })
    .catch(err => {
        console.error('Connection failed', err);
    });

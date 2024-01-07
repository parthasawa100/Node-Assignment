require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const userRoutes = require('./routes/user');
const adminRoutes = require('./routes/admin');

const app = express();
const port = 3000;
mongoose.connect(process.env.MONGO_URI,
    { useNewUrlParser: true, useUnifiedTopology: true }
);
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

app.use(express.json());
app.use('/users', userRoutes);
app.use('/admin', adminRoutes);

app.listen(port, () => console.log(`Server is running on port ${port}`));

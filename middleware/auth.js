const jwt = require('jsonwebtoken');
const { Admin, User } = require('../models/model');

const authenticate = async (req, res, next) => {
    try {
        const authorizationHeader = req.header('Authorization');

        if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
            throw new Error('Invalid authorization format');
        }

        const token = authorizationHeader.replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        let user;

        if (decoded.admin) {
            user = await Admin.findById(decoded._id).lean();
        } else {
            user = await User.findById(decoded._id).lean();
        }

        if (!user) {
            throw new Error('User not found');
        }

        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

module.exports = authenticate;

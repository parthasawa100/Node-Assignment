const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});

const Admin = mongoose.model('Admin', adminSchema);

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  phone: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  password: { type: String, required: true },
  profileImage: {
    public_id: { type: String, required: true },
    url: { type: String, required: true }
  }
});

const User = mongoose.model('User', userSchema);

module.exports = { Admin, User };

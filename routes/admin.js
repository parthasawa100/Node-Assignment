const express = require('express');
const bcrypt = require('bcrypt');
const cloudinary = require('../utils/cloudinary')
const multer = require('multer');
const jwt = require('jsonwebtoken');
const { Admin, User } = require('../models/model');
const authenticate = require('../middleware/auth');
const validationMiddleware = require('../middleware/validation');

const router = express.Router();
const storage = multer.diskStorage(
  {
    filename: function (req, file, cb) {
      cb(null, file.originalname)
    }
  }
);
const upload = multer({ storage: storage });

// Create Admin
router.post(
  '/createadmin',
  validationMiddleware.validateAdminCreation,
  validationMiddleware.validateRequest,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const adminCount = await Admin.countDocuments();
      if (adminCount === 0) {
        const hashedPassword = await bcrypt.hash(password, 10);
        const admin = new Admin({
          email,
          password: hashedPassword,
        });
        await admin.save();
        res.status(201).json({ message: 'Admin created successfully.' });
      } else {
        authenticate(req, res, async () => {
          const existingAdmin = await Admin.findOne({ email });
          const existingUser = await User.findOne({ email });
          if (existingUser) {
            return res.status(400).json({ error: 'Email Id registered as User' });
          }
          if (existingAdmin) {
            return res.status(400).json({ error: 'Admin with this email already exists.' });
          }
          const hashedPassword = await bcrypt.hash(password, 10);
          const admin = new Admin({
            email,
            password: hashedPassword,
          });
          await admin.save();
          res.status(201).json({ message: 'Admin created successfully.' });
        });
      }
    } catch (error) {
      res.status(500).json({ error: 'Internal server error.' });
    }
  }
);


router.post('/login', validationMiddleware.validateLogin, validationMiddleware.validateRequest, async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    const isPasswordMatch = await bcrypt.compare(password, admin.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    const token = jwt.sign({ _id: admin._id, admin: true }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

router.get('/allusers', authenticate, async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

router.patch(
  '/modifyuser/:userId',
  upload.single('profileImage'),
  authenticate,
  validationMiddleware.validateProfileModification,
  validationMiddleware.validateRequest,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { name } = req.body;
      const foundUser = await User.findById(userId);
      if (!foundUser) {
        throw new Error('User not found');
      }
      foundUser.name = name || foundUser.name;
      if (req.file) {
        const ImgId = foundUser.profileImage.public_id;
        if (ImgId) {
          await cloudinary.uploader.destroy(ImgId);
        }
        const result = await cloudinary.uploader.upload(req.file.path, {
          folder: 'Internship',
        });
        foundUser.profileImage = {
          public_id: result.public_id,
          url: result.secure_url,
        };
      }
      await foundUser.save();
      res.json({ message: 'User details modified successfully.' });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error.' });
    }
  }
);
router.delete('/deleteuser/:userId', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findByIdAndDelete(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }
    res.json({ message: 'User deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;

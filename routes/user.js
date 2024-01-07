const express = require('express');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/model');
const authenticate = require('../middleware/auth');
const validationMiddleware = require('../middleware/validation');
const cloudinary = require('../utils/cloudinary')
const router = express.Router();
const storage = multer.diskStorage(
  {
    filename: function (req, file, cb) {
      cb(null, file.originalname)
    }
  }
);
const upload = multer({ storage: storage });

router.post(
  '/signup',
  upload.single('profileImage'),
  validationMiddleware.validateUserCreation,
  validationMiddleware.validateRequest,
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'File not provided.' });
      }
      const { email, phone, name, password } = req.body;
      if (!email && !phone) {
        return res.status(400).json({ error: 'At least one of email or phone must be provided.' });
      }
      const existingAdmin = await User.Admin.findOne({ email });
      if (existingAdmin) {
        return res.status(400).json({ error: 'Email Id registerd' });
      }
      const existingUser = await User.User.findOne({ $or: [{ email }, { phone }] });
      if (existingUser) {
        return res.status(400).json({ error: 'User with this email or phone already exists.' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);

      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: "internship",
      });
      const user = new User.User({
        email,
        phone,
        name,
        password: hashedPassword,
        profileImage:
        {
          public_id: result.public_id,
          url: result.secure_url,
        },
      });

      await user.save();

      res.status(201).json({ message: 'User created successfully.' });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error.' });
    }
  }
);
router.post(
  '/login',
  validationMiddleware.validateRequest,
  async (req, res) => {
    try {
      const { email, phone, password } = req.body;

      if (!email && !phone) {
        return res.status(400).json({ error: 'Please provide email or phone for login.' });
      }
      const user = await User.User.findOne({ $or: [{ email }, { phone }] });
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials.' });
      }
      if (email) {
        validationMiddleware.validateLogin(req, res, async () => {
          const isPasswordMatch = await bcrypt.compare(password, user.password);

          if (!isPasswordMatch) {
            return res.status(401).json({ error: 'Invalid credentials.' });
          }

          const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
          res.json({ token });
        })

      }
      else {
        const isPasswordMatch = await bcrypt.compare(password, user.password);

        if (!isPasswordMatch) {
          return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ token });
      }


    } catch (error) {
      res.status(500).json({ error: 'Internal server error.' });
    }
  }
);

router.get(
  '/view',
  authenticate,
  validationMiddleware.validateRequest,
  async (req, res) => {
    try {
      const foundUser = await User.User.findById(req.user._id);
      res.json(foundUser);
    }
    catch {
      res.status(500).json({ error: 'Internal server error.' });
    }

  }
)

router.patch(
  '/modifydetails',
  authenticate,
  validationMiddleware.validateProfileModification,
  validationMiddleware.validateRequest,
  upload.single('profileImage'),
  async (req, res) => {
    try {
      const { name } = req.body;
      const foundUser = await User.User.findById(req.user._id);
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


router.delete('/delete', authenticate, async (req, res) => {
  try {
    const deletedUser = await User.User.findByIdAndDelete(req.user._id);
    if (!deletedUser) {
      throw new Error('User not found');
    }
    res.json({ message: 'User deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;

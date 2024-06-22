import User from '../models/User.js';
import Blacklist from '../models/Blacklist.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import multer from 'multer';
import path from 'path';
import config from 'config';
import { generateOTP } from '../utils/generateOTP.js';
// import { sendEmail } from '../middlewares/sendEmail.js';
import { sendOTP } from '../middlewares/sendEmail.js';
import { fileURLToPath } from 'url';
import fs from 'fs';
const jwtSecret = config.get('jwtSecret');
const refreshTokenSecret = config.get('refreshTokenSecret');
const refreshTokenExpire = config.get('refreshTokenExpire');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const checkFileType = (file, cb) => {
  const filetypes = /jpeg|jpg|png|gif/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb('Error: Images Only!');
  }
};


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({ storage }).single('image');

export const register = (req, res) => {
    upload(req, res, async (err) => {
      if (err) {
        return res.status(400).json({ error: 'Image upload failed' });
      }
  
      const { name, email, password } = req.body;
  
      if (!name || !email || !password) {
        return res.status(400).json({ error: 'Please enter all fields' });
      }
  
      try {
        let user = await User.findOne({ email });
        if (user) {
          return res.status(400).json({ error: 'User already exists' });
        }
  
        user = new User({
          name,
          email,
          password,
          avatar: req.file ? req.file.path : '',
        });
  
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
  
        const payload = {
          user: {
            id: user.id,
          },
        };
  
        const accessToken = jwt.sign(payload, jwtSecret, { expiresIn: 3600 });
        const refreshToken = jwt.sign(payload, refreshTokenSecret, { expiresIn: refreshTokenExpire });
  
        user.refreshToken = refreshToken;
        await user.save();
  
        res.json({ accessToken, refreshToken });
      } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
      }
    });
  };


export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: 'Invalid Credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid Credentials' });
    }

    const payload = {
      user: {
        id: user.id,
      },
    };

    jwt.sign(
      payload,
      'yourJWTSecret',
      { expiresIn: 3600 },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
};

export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    const otp = generateOTP();

    // Save OTP to user in database (for verification)
    user.resetPasswordOTP = otp;
    await user.save();

    await sendOTP(user.email, otp);

    res.json({ message: 'OTP sent to your email' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
};



export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ msg: 'User not found' });
    }

    // Verify OTP
    if (otp !== user.resetPasswordOTP) {
      return res.status(400).json({ msg: 'Invalid OTP' });
    }

    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);

    // Clear the OTP after successful reset
    user.resetPasswordOTP = '';
    await user.save();

    res.json({ msg: 'Password reset successful' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
};


export const logout = async (req, res) => {
  const token = req.header('x-auth-token');
  console.log('in blacklist', token);
  if (!token) {
    return res.status(400).json({ msg: 'No token provided' });
  }
  try {
    // const blacklistedToken = new Blacklist({
    //   token,
    //   expiresAt: new Date(Date.now() + 3600 * 1), // Token expiration time (1 hour for example)
    // });
    // await blacklistedToken.save();
   
    const blacklistedToken = new Blacklist({ 
      token,
      expiresAt: new Date(Date.now() + 3600 * 1),// Token expiration time (1 mnt for example)
     });
    await blacklistedToken.save();

    res.json({ msg: 'User logged out successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
};

export const refreshToken = async (req, res) => {
    const { refreshToken } = req.body;
  
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token is required' });
    }
  
    try {
      const decoded = jwt.verify(refreshToken, refreshTokenSecret);
      const user = await User.findById(decoded.user.id);
  
      if (!user || user.refreshToken !== refreshToken) {
        return res.status(401).json({ error: 'Invalid refresh token' });
      }
  
      const payload = {
        user: {
          id: user.id,
        },
      };
  
      const newAccessToken = jwt.sign(payload, jwtSecret, { expiresIn: 3600 });
      const newRefreshToken = jwt.sign(payload, refreshTokenSecret, { expiresIn: refreshTokenExpire });
  
      user.refreshToken = newRefreshToken;
      await user.save();
  
      res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    } catch (err) {
      console.error(err.message);
      res.status(403).json({ error: 'Invalid refresh token' });
    }
  };
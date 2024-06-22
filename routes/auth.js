import express from 'express';
import { register, login, forgotPassword, resetPassword, logout,refreshToken } from '../controllers/authController.js';
import auth from '../middlewares/auth.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.post('/logout', auth, logout);
router.post('/refresh-token', refreshToken);

export default router;

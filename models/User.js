// models/User.js
import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  avatar: {
    type: String,
  },
  refreshToken: {
    type: String,
  },
  resetPasswordOTP: {
    type: String,
    default: '', // Default value to prevent undefined
  },
});

const User = mongoose.model('User', UserSchema);
export default User;

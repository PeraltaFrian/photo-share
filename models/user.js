//models/user.js
import mongoose from 'mongoose';
import crypto from 'crypto';

const ENCRYPTION_KEY = crypto
  .createHash('sha256')
  .update(process.env.ENCRYPTION_SECRET || 'default_secret')
  .digest();

const IV_LENGTH = 16;

function decrypt(text) {
  if (!text.includes(':')) return text; // fallback for unencrypted values
  const [ivHex, encrypted] = text.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role:     { type: String, enum: ['user', 'admin'], default: 'user' },
  bio:      { type: String },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
}, { timestamps: true });

// Decrypt sensitive fields for JSON responses
userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  try {
    obj.email = decrypt(obj.email);
    obj.bio = obj.bio ? decrypt(obj.bio) : '';
  } catch (e) {
    console.warn('Decryption error:', e);
  }
  delete obj.password;
  delete obj.__v;
  return obj;
};

const User = mongoose.model('User', userSchema);
export default User;

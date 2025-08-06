//routes/profile.js
import express from 'express';
import { body, validationResult } from 'express-validator';
import crypto from 'crypto';
import User from '../models/user.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// === Encryption Setup ===
const ENCRYPTION_KEY = crypto
  .createHash('sha256')
  .update(process.env.ENCRYPTION_SECRET || 'default_secret')
  .digest();

const IV_LENGTH = 16;

// === Encryption Helper Functions ===
function encrypt(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
  if (!text) return '';
  const [ivHex, encrypted] = text.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// === GET /users/me ===
// Return the current user's profile info
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json({
      name: user.name || user.username || 'User',
      username: user.username || '',
      email: decrypt(user.email),
      bio: decrypt(user.bio),
    });
  } catch (err) {
    console.error('Profile fetch error:', err);
    res.status(500).json({ error: 'Failed to retrieve profile' });
  }
});

// === PUT /users/profile ===
// Update current user's profile info
router.put(
  '/profile',
  authenticateToken,
  [
    body('name')
      .trim()
      .isLength({ min: 3, max: 50 })
      .withMessage('Name must be 3–50 characters.')
      .matches(/^[A-Za-z\s]+$/)
      .withMessage('Name must contain only letters and spaces.'),
    body('email')
      .isEmail()
      .withMessage('Invalid email format.')
      .normalizeEmail(),
    body('bio')
      .optional()
      .trim()
      .isLength({ max: 500 })
      .withMessage('Bio must be under 500 characters.')
      .matches(/^[a-zA-Z0-9\s.,!?'"()\-@]*$/)
      .withMessage('Bio contains invalid characters.'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const { name, email, bio } = req.body;

    try {
      const user = await User.findById(req.user.id);
      if (!user) return res.status(404).json({ error: 'User not found' });

      user.name = name;
      user.email = encrypt(email);
      user.bio = typeof bio === 'string' && bio.trim() !== '' ? encrypt(bio.trim()) : '';

      await user.save();

      res.json({ message: 'Profile updated successfully.' });
    } catch (err) {
      console.error('Profile update error:', err);
      res.status(500).json({ error: 'Server error during update' });
    }
  }
);

export default router;

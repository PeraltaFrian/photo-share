//js/user-dashboard.js
import { apiFetch } from './api.js';

let csrfToken = '';

async function fetchCsrfToken() {
  try {
    const res = await fetch('/csrf-token', { credentials: 'include' });
    if (!res.ok) throw new Error('Failed to fetch CSRF token');
    const data = await res.json();
    csrfToken = data.csrfToken;
  } catch (err) {
    console.error('Error fetching CSRF token:', err);
  }
}

async function displayUserProfile() {
  try {
    const res = await fetch('/users/me', { credentials: 'include' });

    // If user is not authenticated, redirect
    if (res.status === 401 || res.status === 403) {
      window.location.href = 'login.html';
      return;
    }

    if (!res.ok) throw new Error('Failed to fetch user info');

    const data = await res.json();
    console.log('User info from /users/me:', data);

    const username = data.name || data.username || 'User';
    const email = data.email || '';
    const bio = data.bio || '';

    document.getElementById('welcomeMessage').textContent = `Welcome, ${escapeHtml(username)}!`;
    document.getElementById('username').textContent = escapeHtml(username);
    document.getElementById('emailDisplay').textContent = escapeHtml(email);

    // Pre-fill the form
    document.getElementById('name').value = username;
    document.getElementById('email').value = email;
    document.getElementById('bio').value = bio;
  } catch (err) {
    console.error('Error fetching user profile:', err);
    document.getElementById('welcomeMessage').textContent = '';
    document.getElementById('username').textContent = 'N/A';
    document.getElementById('emailDisplay').textContent = 'N/A';
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"'`=\/]/g, (s) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '`': '&#x60;',
    '=': '&#x3D;',
    '/': '&#x2F;',
  }[s]));
}

function setupLogout() {
  const logoutBtn = document.getElementById('logoutBtn');
  logoutBtn?.addEventListener('click', async () => {
    try {
      await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
    } catch (e) {
      console.error('Logout error:', e);
    } finally {
      localStorage.removeItem('token');
      window.location.href = 'login.html';
    }
  });
}

// Sanitize input by removing any HTML tags and special chars except allowed ones
function sanitizeInput(input) {
  // Remove any HTML tags completely
  input = input.replace(/<\/?[^>]+(>|$)/g, "");
  // Remove special characters except letters, numbers, spaces, and some punctuation allowed in bio
  return input.replace(/[^a-zA-Z0-9\s.,!?'"()\-@]/g, '');
}

function setupProfileUpdate() {
  const form = document.getElementById('profileUpdateForm');
  const updateMsg = document.getElementById('updateMessage');

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const rawName = form.name.value.trim();
    const rawEmail = form.email.value.trim();
    const rawBio = form.bio.value.trim();

    const name = sanitizeInput(rawName);
    const email = sanitizeInput(rawEmail);
    const bio = sanitizeInput(rawBio);

    // Validate name: letters and spaces only, length 3-50
    if (!/^[A-Za-z\s]{3,50}$/.test(name)) {
      updateMsg.textContent = 'Invalid name. Use 3–50 letters and spaces only.';
      return;
    }

    // Validate email format (simple)
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      updateMsg.textContent = 'Invalid email format.';
      return;
    }

    // Validate bio: max 500 chars, no HTML tags or special chars (already sanitized)
    if (bio.length > 500) {
      updateMsg.textContent = 'Bio too long (max 500 characters).';
      return;
    }

    try {
      const res = await apiFetch('/users/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ name, email, bio }),
      });

      if (!res.ok) {
        const errorText = await res.text();
        throw new Error(errorText);
      }

      updateMsg.textContent = 'Profile updated successfully.';
      await displayUserProfile();
    } catch (err) {
      console.error('Update error:', err);
      updateMsg.textContent = 'Error updating profile. Please try again.';
    }
  });
}

async function init() {
  await fetchCsrfToken();
  await displayUserProfile();
  setupLogout();
  setupProfileUpdate();
}

init();

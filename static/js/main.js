/**
 * TraceX - Main Utility Script
 * Handles global DOM helpers, notifications, safe rendering, and session actions.
 */

// Safe text escape helper
function escapeHTML(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Global Toast Notification
function showToast(message, type = 'info') {
  let toastContainer = document.getElementById('toast-container');
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'toast-container';
    toastContainer.style.position = 'fixed';
    toastContainer.style.bottom = '20px';
    toastContainer.style.right = '20px';
    toastContainer.style.zIndex = '9999';
    toastContainer.style.display = 'flex';
    toastContainer.style.flexDirection = 'column';
    toastContainer.style.gap = '8px';
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement('div');
  toast.className = `alert alert-${type}`;
  toast.style.margin = '0';
  toast.style.minWidth = '280px';
  toast.style.maxWidth = '420px';
  toast.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.5)';
  toast.style.animation = 'fadeIn 0.2s ease-in-out';
  toast.textContent = message;

  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 300);
  }, 4000);
}

// Handle User Logout
async function handleLogout() {
  try {
    const res = await fetch('/logout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });
    if (res.ok) {
      window.location.href = '/login';
    } else {
      window.location.href = '/login';
    }
  } catch (err) {
    console.error('Logout failed:', err);
    window.location.href = '/login';
  }
}

// Mobile navigation toggle
document.addEventListener('DOMContentLoaded', () => {
  const toggleBtn = document.querySelector('.mobile-nav-toggle');
  const navLinks = document.querySelector('.nav-links');
  if (toggleBtn && navLinks) {
    toggleBtn.addEventListener('click', () => {
      navLinks.classList.toggle('open');
    });
  }

  // Attach logout handlers to any element with data-logout
  document.querySelectorAll('[data-logout]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      handleLogout();
    });
  });

  // Handle in-page smooth scrolling and active state updates for sidebar links
  document.querySelectorAll('.sidebar-link[href^="#"]').forEach(link => {
    link.addEventListener('click', (e) => {
      const targetId = link.getAttribute('href').substring(1);
      const targetEl = document.getElementById(targetId);
      if (targetEl) {
        e.preventDefault();
        document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
        link.classList.add('active');
        targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });
});

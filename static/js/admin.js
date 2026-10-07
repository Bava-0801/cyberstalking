/**
 * TraceX - Admin Management Client Script
 * Fetches and renders system metrics, user accounts, and security audit logs.
 */

document.addEventListener('DOMContentLoaded', () => {
  fetchAdminStats();
  fetchAdminUsers();
  fetchAdminAuditLogs();
});

// Fetch system-wide admin metrics
async function fetchAdminStats() {
  try {
    const res = await fetch('/stats?scope=global', {
      headers: { 'Accept': 'application/json' }
    });
    if (!res.ok) return;

    const data = await res.json();
    const admUsers = document.getElementById('admin-stat-users');
    const admIncidents = document.getElementById('admin-stat-incidents');
    const admHigh = document.getElementById('admin-stat-high');
    const admMed = document.getElementById('admin-stat-med');
    const admLow = document.getElementById('admin-stat-low');
    const admFlags = document.getElementById('admin-stat-flags');

    if (admUsers) admUsers.textContent = data.total_users ?? 0;
    if (admIncidents) admIncidents.textContent = data.total_incidents ?? 0;
    if (admHigh) admHigh.textContent = data.high_risk ?? 0;
    if (admMed) admMed.textContent = data.medium_risk ?? 0;
    if (admLow) admLow.textContent = data.low_risk ?? 0;
    if (admFlags) admFlags.textContent = data.potential_identity_flags ?? 0;
  } catch (err) {
    console.error('Error loading admin statistics:', err);
  }
}

// Fetch all registered users
async function fetchAdminUsers() {
  const tbody = document.getElementById('admin-users-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/admin/users', {
      headers: { 'Accept': 'application/json' }
    });
    if (!res.ok) return;

    const users = await res.json();
    tbody.innerHTML = '';

    users.forEach(u => {
      const tr = document.createElement('tr');

      // ID
      const tdId = document.createElement('td');
      tdId.textContent = `#${u.id}`;
      tdId.style.fontFamily = 'var(--font-mono)';
      tr.appendChild(tdId);

      // Username
      const tdUser = document.createElement('td');
      tdUser.textContent = u.username;
      tdUser.style.fontWeight = '600';
      tr.appendChild(tdUser);

      // Role
      const tdRole = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = u.role === 'admin' ? 'badge badge-high' : 'badge badge-blue';
      badge.textContent = u.role;
      tdRole.appendChild(badge);
      tr.appendChild(tdRole);

      // Created At
      const tdDate = document.createElement('td');
      tdDate.textContent = u.created_at ? u.created_at.substring(0, 19) : '—';
      tdDate.style.fontSize = '0.785rem';
      tdDate.style.color = 'var(--text-secondary)';
      tr.appendChild(tdDate);

      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error fetching admin users:', err);
  }
}

// Fetch security audit logs
async function fetchAdminAuditLogs() {
  const tbody = document.getElementById('admin-audit-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/admin/audit-logs', {
      headers: { 'Accept': 'application/json' }
    });
    if (!res.ok) return;

    const logs = await res.json();
    tbody.innerHTML = '';

    logs.forEach(log => {
      const tr = document.createElement('tr');

      // Timestamp
      const tdTime = document.createElement('td');
      tdTime.textContent = log.created_at ? log.created_at.substring(0, 19) : '—';
      tdTime.style.fontFamily = 'var(--font-mono)';
      tdTime.style.fontSize = '0.75rem';
      tdTime.style.color = 'var(--text-secondary)';
      tr.appendChild(tdTime);

      // Username
      const tdUser = document.createElement('td');
      tdUser.textContent = log.username || 'System';
      tdUser.style.fontWeight = '500';
      tr.appendChild(tdUser);

      // Action
      const tdAction = document.createElement('td');
      const actionBadge = document.createElement('span');
      if (log.action.includes('FAILED') || log.action.includes('ALERT')) {
        actionBadge.className = 'badge badge-high';
      } else if (log.action.includes('ADMIN')) {
        actionBadge.className = 'badge badge-medium';
      } else {
        actionBadge.className = 'badge badge-neutral';
      }
      actionBadge.textContent = log.action;
      tdAction.appendChild(actionBadge);
      tr.appendChild(tdAction);

      // Details
      const tdDetails = document.createElement('td');
      tdDetails.textContent = log.details || '—';
      tdDetails.style.fontSize = '0.8rem';
      tdDetails.style.color = 'var(--text-secondary)';
      tr.appendChild(tdDetails);

      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error fetching audit logs:', err);
  }
}

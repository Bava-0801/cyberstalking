/**
 * TraceX - Dashboard Controller Script
 * Coordinates stats fetching, incident analyzer submission,
 * evidence upload & hashing, result panel display, and history listing.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Initial data loading
  fetchDashboardStats();
  fetchIncidentHistory();

  // Analyzer Form Setup
  const analyzerForm = document.getElementById('analyzer-form');
  const analyzeBtn = document.getElementById('analyze-submit-btn');
  const evidenceInput = document.getElementById('evidence-file');
  const fileStatusText = document.getElementById('file-upload-status');

  if (evidenceInput && fileStatusText) {
    evidenceInput.addEventListener('change', () => {
      if (evidenceInput.files.length > 0) {
        const file = evidenceInput.files[0];
        fileStatusText.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
      } else {
        fileStatusText.textContent = '';
      }
    });
  }

  if (analyzerForm) {
    analyzerForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const platform = document.getElementById('platform').value;
      const senderUsername = document.getElementById('sender-username').value.trim();
      const senderName = document.getElementById('sender-name').value.trim();
      const profileUrl = document.getElementById('profile-url').value.trim();
      const message = document.getElementById('message-content').value.trim();

      if (!message) {
        showToast('Please enter the suspicious message text to analyze.', 'warning');
        return;
      }

      const originalBtnText = analyzeBtn.textContent;
      analyzeBtn.disabled = true;

      let uploadedFilename = null;
      let uploadedHash = null;

      try {
        // Step 1: Upload evidence file if selected
        if (evidenceInput && evidenceInput.files.length > 0) {
          analyzeBtn.textContent = 'Uploading evidence...';
          const file = evidenceInput.files[0];

          // Check file size (10 MB client check)
          if (file.size > 10 * 1024 * 1024) {
            showToast('Evidence file exceeds maximum allowed size of 10 MB.', 'danger');
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = originalBtnText;
            return;
          }

          const formData = new FormData();
          formData.append('file', file);

          const uploadRes = await fetch('/upload-evidence', {
            method: 'POST',
            body: formData
          });

          const uploadData = await uploadRes.json().catch(() => ({}));

          if (!uploadRes.ok || !uploadData.success) {
            showToast(uploadData.error || 'Failed to upload evidence.', 'danger');
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = originalBtnText;
            return;
          }

          uploadedFilename = uploadData.filename;
          uploadedHash = uploadData.hash;
          showToast('Evidence file uploaded and SHA-256 hash verified.', 'info');
        }

        // Step 2: Send for AI & Behavioural analysis
        analyzeBtn.textContent = 'Analyzing with TraceX AI...';

        const analyzePayload = {
          platform: platform,
          sender_username: senderUsername,
          sender_name: senderName,
          profile_url: profileUrl,
          message: message,
          evidence_filename: uploadedFilename,
          evidence_hash: uploadedHash
        };

        const response = await fetch('/analyze', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify(analyzePayload)
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok || !data.success) {
          showToast(data.error || 'Analysis failed. Please check your input.', 'danger');
          analyzeBtn.disabled = false;
          analyzeBtn.textContent = originalBtnText;
          return;
        }

        // Step 3: Render Result Panel
        renderAnalysisResult(data);
        showToast('Analysis complete. Incident recorded.', 'success');

        // Step 4: Refresh stats and history list
        fetchDashboardStats();
        fetchIncidentHistory();

        // Reset file attachment input
        if (evidenceInput) evidenceInput.value = '';
        if (fileStatusText) fileStatusText.textContent = '';

        // Scroll smoothly to results
        const resultPanel = document.getElementById('result-panel-container');
        if (resultPanel) {
          resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

      } catch (err) {
        console.error('Analysis error:', err);
        showToast('An error occurred during communication with the server.', 'danger');
      } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = originalBtnText;
      }
    });
  }
});

// Fetch Real Dashboard Statistics
async function fetchDashboardStats() {
  try {
    const res = await fetch('/stats?scope=user', {
      headers: { 'Accept': 'application/json' }
    });
    if (!res.ok) return;

    const stats = await res.json();
    const statTotal = document.getElementById('stat-total-incidents');
    const statHigh = document.getElementById('stat-high-risk');
    const statMed = document.getElementById('stat-med-risk');
    const statLow = document.getElementById('stat-low-risk');
    const statFlags = document.getElementById('stat-id-flags');

    if (statTotal) statTotal.textContent = stats.total_incidents ?? 0;
    if (statHigh) statHigh.textContent = stats.high_risk ?? 0;
    if (statMed) statMed.textContent = stats.medium_risk ?? 0;
    if (statLow) statLow.textContent = stats.low_risk ?? 0;
    if (statFlags) statFlags.textContent = stats.potential_identity_flags ?? 0;
  } catch (err) {
    console.error('Error fetching dashboard statistics:', err);
  }
}

// Fetch Incident History
async function fetchIncidentHistory() {
  const tbody = document.getElementById('incidents-table-body');
  const emptyState = document.getElementById('incidents-empty-state');
  if (!tbody) return;

  try {
    const res = await fetch('/incidents', {
      headers: { 'Accept': 'application/json' }
    });
    if (!res.ok) return;

    const incidents = await res.json();
    tbody.innerHTML = '';

    if (!incidents || incidents.length === 0) {
      if (emptyState) emptyState.style.display = 'block';
      return;
    }

    if (emptyState) emptyState.style.display = 'none';

    incidents.forEach(inc => {
      const tr = document.createElement('tr');

      // ID
      const tdId = document.createElement('td');
      tdId.textContent = `#${inc.id}`;
      tdId.style.fontFamily = 'var(--font-mono)';
      tdId.style.fontWeight = '600';
      tr.appendChild(tdId);

      // Platform
      const tdPlat = document.createElement('td');
      tdPlat.textContent = inc.platform || 'Unknown';
      tr.appendChild(tdPlat);

      // Sender
      const tdSender = document.createElement('td');
      const senderText = inc.sender_username ? `@${inc.sender_username}` : (inc.sender_name || 'Unspecified');
      tdSender.textContent = senderText;
      tr.appendChild(tdSender);

      // Risk Badge
      const tdRisk = document.createElement('td');
      const riskBadge = document.createElement('span');
      riskBadge.className = `badge badge-${inc.risk_level.toLowerCase()}`;
      riskBadge.textContent = inc.risk_level;
      tdRisk.appendChild(riskBadge);
      tr.appendChild(tdRisk);

      // Score
      const tdScore = document.createElement('td');
      tdScore.textContent = `${inc.risk_score} / 100`;
      tdScore.style.fontFamily = 'var(--font-mono)';
      tr.appendChild(tdScore);

      // Identity Status
      const tdIdStatus = document.createElement('td');
      const idBadge = document.createElement('span');
      if (inc.fake_id_status === 'SUSPICIOUS') {
        idBadge.className = 'badge badge-high';
      } else if (inc.fake_id_status === 'UNVERIFIED') {
        idBadge.className = 'badge badge-medium';
      } else {
        idBadge.className = 'badge badge-low';
      }
      idBadge.textContent = inc.fake_id_status;
      tdIdStatus.appendChild(idBadge);
      tr.appendChild(tdIdStatus);

      // Date
      const tdDate = document.createElement('td');
      tdDate.textContent = inc.created_at ? inc.created_at.substring(0, 16) : '—';
      tdDate.style.fontSize = '0.785rem';
      tdDate.style.color = 'var(--text-secondary)';
      tr.appendChild(tdDate);

      // Action
      const tdAction = document.createElement('td');
      const viewLink = document.createElement('a');
      viewLink.href = `/incidents/${inc.id}`;
      viewLink.className = 'btn btn-secondary btn-sm';
      viewLink.textContent = 'View Details';
      tdAction.appendChild(viewLink);
      tr.appendChild(tdAction);

      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error fetching incident history:', err);
  }
}

// Render Result Panel
function renderAnalysisResult(data) {
  const panel = document.getElementById('result-panel-container');
  if (!panel) return;

  panel.style.display = 'block';

  // Risk Score & Level
  const scoreNum = document.getElementById('res-score-number');
  const levelBadge = document.getElementById('res-level-badge');
  const barFill = document.getElementById('res-score-bar-fill');

  const riskScore = data.risk_score ?? 0;
  const riskLevel = data.risk_level ?? 'LOW';

  if (scoreNum) scoreNum.textContent = `${riskScore}`;
  if (levelBadge) {
    levelBadge.textContent = riskLevel;
    levelBadge.className = `badge badge-${riskLevel.toLowerCase()}`;
  }

  if (barFill) {
    barFill.style.width = `${riskScore}%`;
    if (riskLevel === 'HIGH') {
      barFill.style.backgroundColor = 'var(--risk-high)';
    } else if (riskLevel === 'MEDIUM') {
      barFill.style.backgroundColor = 'var(--risk-medium)';
    } else {
      barFill.style.backgroundColor = 'var(--risk-low)';
    }
  }

  // Meta details
  const resPlatform = document.getElementById('res-platform');
  const resSender = document.getElementById('res-sender');
  const resPrediction = document.getElementById('res-prediction');
  const resConfidence = document.getElementById('res-confidence');

  if (resPlatform) resPlatform.textContent = data.platform;
  if (resSender) {
    const handle = data.sender_username ? `@${data.sender_username}` : '';
    const name = data.sender_name ? ` (${data.sender_name})` : '';
    resSender.textContent = (handle + name) || 'Unspecified';
  }
  if (resPrediction) {
    resPrediction.textContent = data.ai_prediction ? (data.ai_prediction.charAt(0).toUpperCase() + data.ai_prediction.slice(1)) : 'Unknown';
  }
  if (resConfidence) {
    resConfidence.textContent = `${data.ai_confidence}%`;
  }

  // Behavioural Patterns
  const patternsList = document.getElementById('res-patterns-list');
  if (patternsList) {
    patternsList.innerHTML = '';
    const patterns = data.detected_patterns || [];
    if (patterns.length === 0 || patterns[0] === 'No strong suspicious pattern detected') {
      const li = document.createElement('li');
      li.style.color = 'var(--text-secondary)';
      li.style.fontSize = '0.825rem';
      li.textContent = 'No strong suspicious pattern detected';
      patternsList.appendChild(li);
    } else {
      patterns.forEach(p => {
        const li = document.createElement('li');
        li.className = 'pattern-item';
        li.textContent = `• ${p}`;
        patternsList.appendChild(li);
      });
    }
  }

  // Potential Identity Indicators
  const idStatusBadge = document.getElementById('res-id-status-badge');
  const idIndicatorsList = document.getElementById('res-id-indicators-list');

  if (idStatusBadge) {
    idStatusBadge.textContent = data.fake_id_status;
    if (data.fake_id_status === 'SUSPICIOUS') {
      idStatusBadge.className = 'badge badge-high';
    } else if (data.fake_id_status === 'UNVERIFIED') {
      idStatusBadge.className = 'badge badge-medium';
    } else {
      idStatusBadge.className = 'badge badge-low';
    }
  }

  if (idIndicatorsList) {
    idIndicatorsList.innerHTML = '';
    const indicators = data.fake_id_indicators || [];
    indicators.forEach(ind => {
      const li = document.createElement('li');
      li.style.fontSize = '0.825rem';
      li.style.color = 'var(--text-secondary)';
      li.style.marginBottom = '4px';
      li.textContent = `• ${ind}`;
      idIndicatorsList.appendChild(li);
    });
  }

  // Evidence & Hash
  const evidenceRow = document.getElementById('res-evidence-row');
  const evidenceFilenameSpan = document.getElementById('res-evidence-filename');
  const evidenceLink = document.getElementById('res-evidence-link');
  const hashVal = document.getElementById('res-evidence-hash');

  if (data.evidence_filename) {
    if (evidenceRow) evidenceRow.style.display = 'flex';
    if (evidenceFilenameSpan) evidenceFilenameSpan.textContent = data.evidence_filename;
    if (evidenceLink) {
      evidenceLink.textContent = 'View File';
      evidenceLink.href = `/evidence/${encodeURIComponent(data.evidence_filename)}`;
    }
    if (hashVal) {
      hashVal.textContent = data.evidence_hash || 'SHA-256 not available';
      hashVal.title = data.evidence_hash || '';
    }
  } else {
    if (evidenceRow) evidenceRow.style.display = 'none';
  }
}

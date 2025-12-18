// =========================
// DASHBOARD STATS MANAGER
// =========================

const API_BASE = window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost'
    ? "http://127.0.0.1:5000"
    : "";
let refreshInterval = null;

// =========================
// 0. UPDATE USER GREETING
// =========================
function updateUserGreeting() {
    try {
        const userData = JSON.parse(localStorage.getItem('currentUser'));
        if (userData) {
            // Update username
            const usernameDisplay = document.getElementById('username-display');
            if (usernameDisplay) {
                // Ensure username is properly capitalized
                const username = userData.username || 'User';
                usernameDisplay.textContent = username.charAt(0).toUpperCase() + username.slice(1).toLowerCase();
            }

            // Update role if available
            const roleDisplay = document.getElementById('user-role-display');
            if (roleDisplay) {
                roleDisplay.textContent = userData.is_admin ? 'Administrator' : 'Security Analyst';
            }

            // Update last login time
            const lastLoginDisplay = document.getElementById('last-login-time');
            if (lastLoginDisplay) {
                const now = new Date();
                lastLoginDisplay.textContent = now.toLocaleString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    year: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    hour12: true
                });
            }
        }
    } catch (error) {
        console.error('Error updating user greeting:', error);
    }
}

// =========================
// 1. FETCH DASHBOARD STATS
// =========================
async function loadDashboardStats() {
    try {
        showLoadingState();
        const res = await fetch(`${API_BASE}/dashboard/stats`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const data = await res.json();
        updateCircularCharts(data);
        updateLatestIncidents(data);
        updatePieChart();
        updateDepartmentSummary(data);
        hideLoadingState();
    } catch (err) {
        console.error("Dashboard load error:", err);
        showErrorState();
        hideLoadingState();
    }
}

// =========================
// 2. UPDATE CIRCULAR CHARTS
// =========================
function updateCircularCharts(data) {
    const charts = [
        { selector: "#email-stat", data: data.email, label: "Email" },
        { selector: "#sms-stat", data: data.sms, label: "SMS" },
        { selector: "#url-stat", data: data.url, label: "URL" }
    ];

    charts.forEach(({ selector, data: chartData, label }) => {
        const card = document.querySelector(`${selector} .stat.card`);
        if (!card) return;

        const circle = card.querySelector(".circle");
        const safePercent = chartData.safe_percent || 100;
        const risk = chartData.risk || "Low";
        const riskColor = chartData.risk_color || "var(--good)";
        const latest = chartData.latest || "No scans yet";
        const total = chartData.total || 0;

        // Update circle chart
        if (circle) {
            const color = safePercent >= 70 ? "var(--good)" : safePercent >= 40 ? "var(--warn)" : "var(--danger)";
            circle.style.background = `conic-gradient(${color} 0 ${safePercent}%, rgba(255,255,255,0.04) ${safePercent}% 100%)`;
            circle.textContent = `${safePercent}%`;
            circle.style.transition = "all 0.5s ease";
        }

        // Update risk indicator
        const riskElement = card.querySelector(".risk-indicator strong");
        if (riskElement) {
            riskElement.textContent = risk;
            riskElement.style.color = riskColor;
        }

        // Update latest scan
        const latestElement = card.querySelector(".hint");
        if (latestElement) {
            latestElement.textContent = `Latest: ${latest}`;
        }

        // Add animation
        card.style.animation = "fadeInUp 0.5s ease";
    });
}

// =========================
// 3. UPDATE LATEST INCIDENTS TABLE
// =========================
async function updateLatestIncidents(data) {
    // If no data is provided, fetch fresh data
    if (!data) {
        try {
            const res = await fetch(`${API_BASE}/dashboard/stats`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            data = await res.json();
        } catch (err) {
            console.error("Failed to refresh incidents:", err);
            return;
        }
    }

    const tbody = document.querySelector("#latest-incidents tbody");
    if (!tbody) return;

    // Add loading indicator
    tbody.innerHTML = `<tr><td colspan="2" style="text-align: center; padding: 20px; color: var(--muted);">Loading...</td></tr>`;

    // Update count
    const countElement = document.getElementById('latest-incidents-count');
    if (countElement) {
        countElement.textContent = `${data.latest ? data.latest.length : 0} incidents`;
    }

    // Small delay for better UX
    setTimeout(() => {
        // Clear existing rows
        tbody.innerHTML = "";

        // Add new rows
        if (data.latest && data.latest.length > 0) {
            data.latest.slice(0, 5).forEach(item => {
                const tr = document.createElement("tr");
                const type = document.createElement("td");
                const summary = document.createElement("td");

                type.textContent = item.type || "Unknown";
                summary.textContent = item.summary || "No details available";

                tr.appendChild(type);
                tr.appendChild(summary);
                tbody.appendChild(tr);
            });
        } else {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 2;
            td.textContent = "No recent incidents";
            td.style.textAlign = "center";
            td.style.padding = "20px";
            td.style.color = "var(--muted)";
            tr.appendChild(td);
            tbody.appendChild(tr);
        }
    }, 300); // Small delay for better UX
}

// Refresh latest incidents function (called by button)
function refreshIncidents() {
    updateLatestIncidents();
}

// =========================
// 4. UPDATE PIE CHART
// =========================
// =========================
// 4. UPDATE PIE CHART
// =========================
async function updatePieChart(data) {
    try {
        if (!data) {
            const res = await fetch(`${API_BASE}/stats/pie`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            data = await res.json();
        }

        // Backward compatibility if data structure is old
        const phishing = data.phishing || 0;
        const suspicious = data.suspicious || 0;
        const safe = data.safe || data.non_phishing || 0;
        const total = phishing + suspicious + safe;

        // Update stats display (number of tests done)
        const statsElement = document.getElementById("pie-chart-stats");
        if (statsElement) {
            statsElement.textContent = `Tests: ${total}`;
        }

        if (total === 0) {
            // Show empty state
            const pieContainer = document.getElementById("pie-chart-container");
            if (pieContainer) {
                pieContainer.innerHTML = `
                    <div style="color:var(--muted);text-align:center;padding:40px">
                        <div style="font-size:48px;margin-bottom:12px">📊</div>
                        <div>No scans yet</div>
                        <div style="font-size:12px;margin-top:8px">Run tests to see statistics</div>
                    </div>
                `;
            }
            return;
        }

        const phishingPercent = (phishing / total) * 100;
        const suspiciousPercent = (suspicious / total) * 100;
        const safePercent = (safe / total) * 100;

        // Create pie chart SVG
        const pieContainer = document.getElementById("pie-chart-container");
        if (!pieContainer) return;

        const size = 120;
        const radius = size / 2 - 5;
        const center = size / 2;
        const circumference = 2 * Math.PI * radius;

        // Calculate arc lengths
        const phishingArcLength = (phishingPercent / 100) * circumference;
        const suspiciousArcLength = (suspiciousPercent / 100) * circumference;
        const safeArcLength = (safePercent / 100) * circumference;

        // Calculate offsets
        // Phishing starts at -90deg (top)
        const suspiciousOffset = -phishingArcLength;
        const safeOffset = -(phishingArcLength + suspiciousArcLength);

        pieContainer.innerHTML = `
            <div style="position:relative;width:${size}px;height:${size}px;margin:0 auto;">
                <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" 
                     style="transform: rotate(-90deg); position:absolute; top:0; left:0; z-index:1;">
                    <!-- Background circle -->
                    <circle cx="${center}" cy="${center}" r="${radius}" 
                            fill="none" stroke="rgba(41, 29, 29, 0.01)" stroke-width="8"/>
                    
                    <!-- Phishing segment (RED) -->
                    <circle cx="${center}" cy="${center}" r="${radius}" 
                            fill="none" stroke="#ff4444" stroke-width="8"
                            stroke-dasharray="${phishingArcLength} ${circumference}"
                            stroke-dashoffset="0"
                            style="transition: stroke-dasharray 0.8s ease;"/>
                    
                    <!-- Suspicious segment (YELLOW/ORANGE) - starts after phishing -->
                    <circle cx="${center}" cy="${center}" r="${radius}" 
                            fill="none" stroke="#f59e0b" stroke-width="8"
                            stroke-dasharray="${suspiciousArcLength} ${circumference}"
                            stroke-dashoffset="${suspiciousOffset}"
                            style="transition: stroke-dasharray 0.8s ease;"/>

                    <!-- Safe segment (GREEN) - starts after suspicious -->
                    <circle cx="${center}" cy="${center}" r="${radius}" 
                            fill="none" stroke="#00C851" stroke-width="8"
                            stroke-dasharray="${safeArcLength} ${circumference}"
                            stroke-dashoffset="${safeOffset}"
                            style="transition: stroke-dasharray 0.8s ease;"/>
                </svg>
                <div class="pie-chart-center" style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);z-index:10;text-align:center;pointer-events:none;width:100%;">
                    <div style="font-size:24px;font-weight:800;color:var(--text);line-height:1.2">${total}</div>
                    <div style="font-size:12px;color:var(--muted);margin-top:4px">Total Scans</div>
                </div>
            </div>
            <div class="pie-legend" style="margin-top:20px">
                <div class="pie-legend-item">
                    <span class="pie-color" style="background:#ff4444;width:12px;height:12px;border-radius:50%;display:inline-block;margin-right:8px;"></span>
                    <span>Phishing: ${phishing} (${phishingPercent.toFixed(1)}%)</span>
                </div>
                <div class="pie-legend-item">
                    <span class="pie-color" style="background:#f59e0b;width:12px;height:12px;border-radius:50%;display:inline-block;margin-right:8px;"></span>
                    <span>Suspicious: ${suspicious} (${suspiciousPercent.toFixed(1)}%)</span>
                </div>
                <div class="pie-legend-item">
                    <span class="pie-color" style="background:#00C851;width:12px;height:12px;border-radius:50%;display:inline-block;margin-right:8px;"></span>
                    <span>Safe: ${safe} (${safePercent.toFixed(1)}%)</span>
                </div>
            </div>
        `;
    } catch (err) {
        console.error("Pie chart error:", err);
        const pieContainer = document.getElementById("pie-chart-container");
        if (pieContainer) {
            pieContainer.innerHTML = `<div style="color:var(--muted);text-align:center;padding:40px">Error loading chart</div>`;
        }
    }
}

// Refresh pie chart function (called by button)
async function refreshPieChart() {
    const container = document.getElementById('pie-chart-container');
    if (!container) return;

    // Show loading state
    container.innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">Refreshing chart data...</div>';

    try {
        // Fetch fresh data
        const res = await fetch(`${API_BASE}/dashboard/stats`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        // Update the pie chart with fresh data
        updatePieChart(data);
    } catch (err) {
        console.error("Failed to refresh pie chart:", err);
        container.innerHTML = '<div style="color:var(--danger);text-align:center;padding:20px">Failed to load data</div>';
    }
}

// Make functions globally accessible
window.refreshPieChart = refreshPieChart;
window.refreshIncidents = refreshIncidents;
window.updatePieChart = updatePieChart;
window.updateBarChart = updateBarChart;
window.updateLatestIncidents = updateLatestIncidents;
window.performSearch = performSearch;
window.loadDashboardStats = loadDashboardStats;

// =========================
// 5. UPDATE DEPARTMENT SUMMARY
// =========================
function updateDepartmentSummary(data) {
    const tbody = document.querySelector(".col-12 tbody");
    if (!tbody) return;

    const departments = [
        { name: "Email", stats: data.email },
        { name: "SMS", stats: data.sms },
        { name: "URL", stats: data.url }
    ];

    tbody.innerHTML = "";
    departments.forEach((dept, index) => {
        const tr = document.createElement("tr");
        tr.style.animation = `fadeIn 0.3s ease ${index * 0.1}s both`;

        const handled = dept.stats.total || 0;
        const open = dept.stats.suspicious + dept.stats.phishing || 0;
        const avgResponse = "1h 12m"; // Placeholder for now

        tr.innerHTML = `
            <td>${dept.name}</td>
            <td>${handled.toLocaleString()}</td>
            <td style="color:${open > 0 ? 'var(--warn)' : 'var(--good)'}">${open}</td>
            <td>${avgResponse}</td>
        `;
        tbody.appendChild(tr);
    });
}

// =========================
// 6. UPDATE BAR CHART
// =========================
async function updateBarChart() {
    try {
        const department = document.getElementById("bar-chart-department")?.value || "all";
        const period = document.getElementById("bar-chart-period")?.value || "daily";

        const res = await fetch(`${API_BASE}/stats/bar?department=${department}&period=${period}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const data = await res.json();
        renderBarChart(data);
    } catch (err) {
        console.error("Bar chart error:", err);
        const container = document.getElementById("bar-chart-container");
        if (container) {
            container.innerHTML = `<div style="color:var(--muted);text-align:center;padding:40px">Error loading chart data</div>`;
        }
    }
}

function renderBarChart(data) {
    const container = document.getElementById("bar-chart-container");
    if (!container) return;

    if (!data.data || data.data.length === 0) {
        container.innerHTML = `<div style="color:var(--muted);text-align:center;padding:40px">No data available for selected period</div>`;
        return;
    }

    // Calculate max value for scaling
    const maxValue = Math.max(...data.data.map(d => d.total), 1);
    const chartHeight = 180;
    const barWidth = 40;
    const barGap = 12;
    const groupWidth = barWidth * 2 + barGap;
    const totalWidth = data.data.length * groupWidth + (data.data.length - 1) * 20;

    let chartHTML = `
        <div style="display:flex;align-items:flex-end;justify-content:center;gap:20px;height:${chartHeight}px;padding:10px 0;overflow-x:auto;">
    `;

    data.data.forEach((point, index) => {
        const safeHeight = point.safe > 0 ? (point.safe / maxValue) * chartHeight : 0;
        const phishingHeight = point.phishing > 0 ? (point.phishing / maxValue) * chartHeight : 0;
        const maxBarHeight = Math.max(safeHeight, phishingHeight, 10); // Minimum 10px for visibility

        chartHTML += `
            <div style="display:flex;flex-direction:column;align-items:center;gap:8px;min-width:${groupWidth}px;">
                <div style="display:flex;align-items:flex-end;gap:${barGap}px;height:${chartHeight}px;position:relative;">
                    <!-- Safe bar (green) -->
                    <div style="position:relative;width:${barWidth}px;">
                        <div class="bar-safe" 
                             style="width:${barWidth}px;height:${safeHeight || 0}px;background:var(--good);border-radius:6px 6px 0 0;transition:height 0.5s ease;cursor:pointer;min-height:${safeHeight > 0 ? '4px' : '0'};"
                             title="Safe: ${point.safe}">
                        </div>
                        ${safeHeight > 0 ? `<div style="position:absolute;bottom:${safeHeight}px;left:50%;transform:translateX(-50%);font-size:10px;color:var(--good);font-weight:700;white-space:nowrap;">${point.safe}</div>` : ''}
                    </div>
                    <!-- Phishing bar (red) -->
                    <div style="position:relative;width:${barWidth}px;">
                        <div class="bar-phishing" 
                             style="width:${barWidth}px;height:${phishingHeight || 0}px;background:var(--danger);border-radius:6px 6px 0 0;transition:height 0.5s ease;cursor:pointer;min-height:${phishingHeight > 0 ? '4px' : '0'};"
                             title="Phishing: ${point.phishing}">
                        </div>
                        ${phishingHeight > 0 ? `<div style="position:absolute;bottom:${phishingHeight}px;left:50%;transform:translateX(-50%);font-size:10px;color:var(--danger);font-weight:700;white-space:nowrap;">${point.phishing}</div>` : ''}
                    </div>
                </div>
                <div style="font-size:12px;color:var(--muted);text-align:center;margin-top:8px;font-weight:600;">
                    ${point.label}
                </div>
                <div style="font-size:10px;color:var(--muted);text-align:center;opacity:0.7;">
                    ${point.full_label}
                </div>
            </div>
        `;
    });

    chartHTML += `</div>`;

    // Add legend
    chartHTML += `
        <div style="display:flex;justify-content:center;gap:24px;margin-top:16px;padding-top:16px;border-top:1px solid rgba(255,255,255,0.05);">
            <div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--muted);">
                <div style="width:16px;height:16px;background:var(--good);border-radius:4px;"></div>
                <span>Safe</span>
            </div>
            <div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--muted);">
                <div style="width:16px;height:16px;background:var(--danger);border-radius:4px;"></div>
                <span>Phishing</span>
            </div>
        </div>
    `;

    container.innerHTML = chartHTML;

    // Add hover effects
    container.querySelectorAll('.bar-safe, .bar-phishing').forEach(bar => {
        bar.addEventListener('mouseenter', function () {
            this.style.opacity = '0.8';
            this.style.transform = 'scaleY(1.05)';
        });
        bar.addEventListener('mouseleave', function () {
            this.style.opacity = '1';
            this.style.transform = 'scaleY(1)';
        });
    });
}

// =========================
// 7. LOADING & ERROR STATES
// =========================
function showLoadingState() {
    const cards = document.querySelectorAll(".stat.card, .card");
    cards.forEach(card => {
        card.style.opacity = "0.6";
        card.style.pointerEvents = "none";
    });
}

function hideLoadingState() {
    const cards = document.querySelectorAll(".stat.card, .card");
    cards.forEach(card => {
        card.style.opacity = "1";
        card.style.pointerEvents = "auto";
    });
}

function showErrorState() {
    console.error("Failed to load dashboard data");
    // You can add a toast notification here
}

// =========================
// 8. AUTO-REFRESH
// =========================
function startAutoRefresh(intervalSeconds = 10) {
    // Enable auto-refresh to keep stats current
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }

    refreshInterval = setInterval(() => {
        loadDashboardStats();
    }, intervalSeconds * 1000);

    console.log(`Auto-refresh enabled: every ${intervalSeconds} seconds`);
}

function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
}

// =========================
// 8. SEARCH FUNCTIONALITY
// =========================
function setupSearch() {
    const searchInput = document.getElementById('search-input');
    const searchButton = document.getElementById('search-button');

    if (!searchInput || !searchButton) return;

    // Handle Enter key in search input
    searchInput.addEventListener('keyup', (e) => {
        if (e.key === 'Enter') {
            performSearch();
        }
    });

    // Handle search button click
    searchButton.addEventListener('click', performSearch);
}

// Perform search with current input value
function performSearch() {
    const searchInput = document.getElementById('search-input');
    if (!searchInput) return;

    const query = searchInput.value.trim();
    if (!query) {
        // If search is empty, refresh all data
        if (window.loadDashboardStats) {
            loadDashboardStats();
        }
        return;
    }

    // Show loading state
    const loadingIndicator = document.createElement('div');
    loadingIndicator.textContent = 'Searching...';
    loadingIndicator.style.textAlign = 'center';
    loadingIndicator.style.padding = '20px';
    loadingIndicator.style.color = 'var(--muted)';

    // Replace content with loading indicator
    const contentSections = document.querySelectorAll('.card > .grid > div');
    contentSections.forEach(section => {
        const originalContent = section.innerHTML;
        section.setAttribute('data-original-content', originalContent);
        section.innerHTML = '';
        section.appendChild(loadingIndicator.cloneNode(true));
    });

    // Simulate search (replace with actual search API call)
    setTimeout(() => {
        // For now, just show a message and reload the data
        console.log('Searching for:', query);

        // Show a message that this is a demo
        contentSections.forEach(section => {
            section.innerHTML = `
                <div style="text-align: center; padding: 40px; color: var(--muted);">
                    <div style="margin-bottom: 15px; font-size: 1.2em;">Search Results for: "${query}"</div>
                    <div style="margin-bottom: 20px;">Search functionality is currently in demo mode.</div>
                    <button class="btn btn-ghost" onclick="if(window.loadDashboardStats) window.loadDashboardStats()">
                        Return to Dashboard
                    </button>
                </div>
            `;
        });
    }, 1000);
}

// =========================
// 9. EXPORT FUNCTIONALITY
// =========================
function exportToCSV() {
    // Implement CSV export
    console.log("Exporting to CSV...");
}

// =========================
// 10. INITIALIZE
// =========================
document.addEventListener("DOMContentLoaded", () => {
    document.addEventListener("DOMContentLoaded", async () => {

        console.log("DASHBOARD AUTH TOKEN:",
            localStorage.getItem("authToken"));

        // ⬇️ auth check happens AFTER the log
        if (!(await window.auth.isAuthenticated())) {
            localStorage.clear();
            window.location.replace("login.html");
            return;
        }

        // dashboard continues...
    });
    // Update user greeting
    updateUserGreeting();
    loadDashboardStats();
    updateBarChart(); // Load bar chart
    setupSearch();
    setupBarChartFilters();
    // Enable auto-refresh every 10 seconds
    startAutoRefresh(10);

    // Setup export button
    const exportBtn = document.querySelector(".btn-ghost");
    if (exportBtn && exportBtn.textContent.includes("Export")) {
        exportBtn.addEventListener("click", exportToCSV);
    }
});

// =========================
// 11. SETUP BAR CHART FILTERS
// =========================
function setupBarChartFilters() {
    const deptFilter = document.getElementById("bar-chart-department");
    const periodFilter = document.getElementById("bar-chart-period");

    if (deptFilter) {
        deptFilter.addEventListener("change", () => {
            updateBarChart();
        });
    }

    if (periodFilter) {
        periodFilter.addEventListener("change", () => {
            updateBarChart();
        });
    }
}

// Cleanup on page unload
window.addEventListener("beforeunload", () => {
    stopAutoRefresh();
});


  /* =========================================================================
   * CLIENT STATE
   * -------------------------------------------------------------------------
   * SECURITY: localStorage is NOT an authorization store. The only role value
   * used by this UI comes from the Firebase ID token custom claim (see
   * firebase-service.js). The arrays below are an in-memory cache of Firestore
   * listeners; they are never persisted with roles, claims, or proof data.
   * ========================================================================= */
  const DEFAULT_CATEGORIES = [
    "ID Cards",
    "Mobiles & Accessories",
    "Laptops & Chargers",
    "Keys & Fobs",
    "Wallets & Purses",
    "Bags & Backpacks",
    "Books & Notebooks",
    "Clothing & Umbrellas",
    "Electronics",
    "Other Valuables"
  ];

  const DEFAULT_BROADCAST = {
    text: "📢 Notice: Lost property from Orientation Week is held at Security Desk Gate 1 & Central Library."
  };

  const UI_PREFS_KEY = "campusUiPrefs";

  /* NOTE: `getCurrentUser()` and the session object are provided by
     firebase-service.js. Do not redeclare them here — a duplicate top-level
     `let currentSession` in two classic scripts is a fatal SyntaxError, and a
     second session object could disagree with the token-derived role. */
  let cachedItems = [];
  let cachedClaims = [];
  let cachedNotifs = [];
  let cachedUsers = [];
  let cachedComplaints = [];
  let cachedLogs = [];
  let cachedCategories = DEFAULT_CATEGORIES.slice();
  let cachedBroadcast = DEFAULT_BROADCAST;
  let cachedChats = [];
  let currentChatId = "";
  let chatMessages = [];
  let chatReadCache = new Map();
  let chatListUnsub = null;
  let chatThreadUnsub = null;
  let chatThreadSubId = "";
  let lastChatReadSignature = "";
  let notificationPrefs = null;
  let deferredInstallPrompt = null;
  let foregroundMessagingBound = false;
  let pwaInitialized = false;
  let handoverScanner = { stream: null, raf: null, detector: null, running: false };

  function getChats() { return cachedChats; }
  function getItems() { return cachedItems; }
  function getClaims() { return cachedClaims; }
  function getNotifs() { return cachedNotifs; }
  function getUsers() { return cachedUsers; }
  function getComplaints() { return cachedComplaints; }
  function getLogs() { return cachedLogs; }
  function getCategories() { return cachedCategories; }
  function getBroadcast() { return cachedBroadcast; }

  /* Role checks are UX-only. Firestore/Storage rules re-check the ID token
     claim on every read/write, so bypassing these checks gains nothing. */
  function isStaffSession(user) {
    return Boolean(user && (user.role === "faculty" || user.role === "admin"));
  }
  function isAdminSession(user) {
    return Boolean(user && user.role === "admin");
  }
  function itemDateLabel(item) {
    return formatDate(item && (item.createdAt || item.updatedAt || item.date));
  }
  function claimStatusLabel(status) {
    const s = String(status || "pending").toLowerCase();
    if (s === "approved") return "Approved";
    if (s === "rejected") return "Rejected";
    if (s === "returned") return "Returned";
    return "Pending";
  }
  function claimStatusClass(status) {
    const s = String(status || "pending").toLowerCase();
    if (s === "approved") return "approved";
    if (s === "rejected") return "rejected";
    if (s === "returned") return "returned";
    return "pending";
  }
  function complaintStatusClass(status) {
    const s = String(status || "").toLowerCase();
    if (s === "resolved") return "returned";
    if (s === "investigating") return "pending";
    return "custody";
  }
  /* Firestore auto-IDs are [A-Za-z0-9]; validate before interpolating them
     into an inline handler to be extra safe against malformed remote data. */
  function safeDocId(id) {
    const value = String(id || "");
    return /^[A-Za-z0-9_-]{1,128}$/.test(value) ? value : "";
  }
  // Chat ids are `${itemId}_${claimantUid}` and can be longer than an auto-ID.
  function safeChatId(id) {
    const value = String(id || "");
    return /^[A-Za-z0-9_-]{3,260}$/.test(value) ? value : "";
  }
  // Only same-origin absolute paths are accepted for notification targets.
  function safeInternalPath(url) {
    const value = String(url || "").trim();
    if (!value.startsWith("/") || value.startsWith("//")) return "";
    try {
      const parsed = new URL(value, window.location.origin);
      if (parsed.origin !== window.location.origin) return "";
      return parsed.pathname + parsed.search + parsed.hash;
    } catch (e) {
      return "";
    }
  }
  /* Inline handlers receive an encoded value; encodeURIComponent is safe inside
     the double-quoted attribute because auto-IDs contain no quotes. */
  function handlerArg(value) {
    return escapeHtml(jsArg(value));
  }

  /* Non-sensitive UI preferences only. Never put roles/claims/proof here. */
  function getUiPrefs() {
    try { return JSON.parse(localStorage.getItem(UI_PREFS_KEY) || "{}") || {}; }
    catch (e) { return {}; }
  }
  function setUiPref(key, value) {
    try {
      const prefs = getUiPrefs();
      prefs[key] = value;
      localStorage.setItem(UI_PREFS_KEY, JSON.stringify(prefs));
    } catch (e) {}
  }

  /* =========================================================================
   * OUTPUT / FORMATTING HELPERS
   * ========================================================================= */
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /* Encode a value for safe inclusion inside a quoted inline handler. The
     handler must call decodeURIComponent(). Used only for values that cannot
     be represented as static handlers. */
  function jsArg(value) {
    // encodeURIComponent leaves apostrophes alone; percent-encode them too so a
    // value can never terminate the single-quoted JS string inside an onclick
    // attribute after the HTML attribute has been decoded.
    return encodeURIComponent(String(value === null || value === undefined ? "" : value))
      .replace(/'/g, "%27")
      .replace(/"/g, "%22");
  }

  function safeImageUrl(url) {
    if (!url) return "";
    try {
      const parsed = new URL(String(url), window.location.href);
      const localDev = parsed.protocol === "http:" &&
        /^(localhost|127\.0\.0\.1)$/.test(parsed.hostname) &&
        parsed.port === "9199";
      // Only Firebase Storage objects are valid item photos. Reject arbitrary
      // https URLs (tracking pixels, unexpected SVG/HTML content served from a
      // third-party host). Emulator URLs are allowed on localhost only.
      const isFirebaseStorage = parsed.protocol === "https:" && (
        parsed.hostname === "firebasestorage.googleapis.com" ||
        /\.firebasestorage\.app$/i.test(parsed.hostname) ||
        (typeof firebaseConfig !== "undefined" &&
          firebaseConfig.storageBucket &&
          parsed.hostname === firebaseConfig.storageBucket)
      );
      if (isFirebaseStorage || localDev) return parsed.href;
    } catch (e) {}
    return "";
  }

  function toJsDate(value) {
    if (!value) return null;
    if (value instanceof Date) return value;
    if (typeof value.toDate === "function") return value.toDate();
    if (typeof value.seconds === "number") return new Date(value.seconds * 1000);
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  function formatDate(value) {
    const d = toJsDate(value);
    return d ? d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "";
  }

  function formatDateTime(value) {
    const d = toJsDate(value);
    return d ? d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }) : "";
  }

  function timeAgo(value) {
    const d = toJsDate(value);
    if (!d) return "";
    const seconds = Math.floor((Date.now() - d.getTime()) / 1000);
    if (seconds < 60) return "Just now";
    if (seconds < 3600) return Math.floor(seconds / 60) + " min ago";
    if (seconds < 86400) return Math.floor(seconds / 3600) + " hr ago";
    if (seconds < 604800) return Math.floor(seconds / 86400) + " days ago";
    return formatDate(d);
  }

  function normalizeStatus(status) {
    const s = String(status || "pending").toLowerCase();
    return ["pending", "approved", "claimed", "returned", "rejected"].includes(s) ? s : "pending";
  }

  function statusLabel(status) {
    const s = normalizeStatus(status);
    if (s === "approved") return "Approved";
    if (s === "claimed") return "Claimed";
    if (s === "returned") return "Returned";
    if (s === "rejected") return "Rejected";
    return "Pending";
  }

  function showToast(msg) {
    const toast = document.getElementById("toastMessage");
    if (!toast) return;
    toast.textContent = String(msg || "");
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 2500);
  }

  function addLog(text) {
    // Cloud Functions write the authoritative audit trail. This client-side
    // convenience entry is append-only by rule (no update/delete) and is shown
    // immediately in the admin console.
    const entry = { id: "local-" + Date.now(), text, time: "Just now" };
    cachedLogs.unshift(entry);
    if (typeof writeAuditLog === "function") {
      writeAuditLog("client.ui_event", "ui", "", text);
    }
  }

  async function persistCategories(cats) {
    cachedCategories = cats;
    if (typeof saveCategoriesToFirestore === "function") {
      await saveCategoriesToFirestore(cats);
    }
  }

  /* =========================================================================
   * APP VIEW NAVIGATION (Board vs Dashboard)
   * ========================================================================= */
  let currentMainView = "board";
  let boardFilter = "all";
  let activeDashTab = "";
  let pendingPhotoFile = null;
  let pendingPhotoPreviewUrl = "";
  let formReportType = "lost";

  /** Hide the full-screen auth loading overlay once Firebase Auth has settled. */
  function hideAuthOverlay() {
    const overlay = document.getElementById("authLoadingOverlay");
    if (overlay && !overlay.classList.contains("hidden")) {
      overlay.classList.add("hidden");
      setTimeout(() => {
        overlay.style.display = "none";
      }, 400);
    }
  }

  function switchMainView(view) {
    currentMainView = view;
    const tabBoard = document.getElementById("tabBoard");
    const tabDash = document.getElementById("tabDash");
    const boardView = document.getElementById("boardView");
    const dashView = document.getElementById("dashboardView");

    if (view === "board") {
      tabBoard.classList.add("active");
      tabDash.classList.remove("active");
      boardView.style.display = "block";
      dashView.style.display = "none";
      renderBoard();
    } else {
      const user = getCurrentUser();
      if (!user) {
        showToast("Please log in to access your dashboard.");
        setTimeout(() => window.location.href = "login.html", 800);
        return;
      }
      tabDash.classList.add("active");
      tabBoard.classList.remove("active");
      boardView.style.display = "none";
      dashView.style.display = "block";
      initDashboard();
    }
  }

  /* =========================================================================
   * HEADER & AUTH STATE
   * ========================================================================= */
  function renderAuthHeader() {
    const authNav = document.getElementById("authNav");
    const notifBadge = document.getElementById("notifBadge");
    const user = getCurrentUser();

    // Notification counter
    const notifs = getNotifs();
    const unreadCount = notifs.filter(n => !n.read).length;
    notifBadge.textContent = unreadCount;
    notifBadge.style.display = unreadCount > 0 ? "flex" : "none";

    if (user) {
      let roleIcon = "👤";
      let roleClass = "role-student";
      let roleLabel = "Student";

      if (user.role === "admin") {
        roleIcon = "🛡️";
        roleClass = "role-admin";
        roleLabel = "Admin";
      } else if (user.role === "faculty") {
        roleIcon = "🎓";
        roleClass = "role-faculty";
        roleLabel = "Faculty/Staff";
      }

      authNav.innerHTML = `
        <div class="user-badge ${roleClass}" title="${escapeHtml(user.email)}">
          <span>${roleIcon}</span>
          <span><strong>${escapeHtml(user.name.split(" ")[0])}</strong></span>
          <span class="role-pill">${roleLabel}</span>
          <button type="button" class="btn-logout" onclick="handleLogout()">Log out</button>
        </div>
      `;
    } else {
      authNav.innerHTML = `
        <a href="login.html" class="btn-auth-link" id="btnNavLogin">
          <span>Sign In</span>
        </a>
      `;
    }

    renderAdminBanner();
    renderCampusBroadcast();
  }

  async function handleLogout() {
    // Firebase Auth owns the session. Clear only non-sensitive local cache.
    try {
      if (typeof firebaseSignOut === "function") await firebaseSignOut();
    } catch (e) {}
    localStorage.removeItem("campusCurrentUser");
    sessionStorage.removeItem("campusCurrentUser");
    cachedItems = [];
    cachedClaims = [];
    cachedNotifs = [];
    cachedUsers = [];
    cachedComplaints = [];
    cachedLogs = [];
    renderAuthHeader();
    switchMainView("board");
    window.location.href = "login.html";
  }

  /* =========================================================================
   * BROADCAST & ADMIN CONSOLE
   * ========================================================================= */
  function renderAdminBanner() {
    const banner = document.getElementById("adminBanner");
    const user = getCurrentUser();
    if (!banner) return;

    if (isAdminSession(user)) {
      const items = getItems();
      const claims = getClaims();
      const lostCount = items.filter(i => i.type === "lost" && normalizeStatus(i.status) !== "returned").length;
      const foundCount = items.filter(i => i.type === "found" && normalizeStatus(i.status) !== "returned").length;
      const pendingCount = items.filter(i => normalizeStatus(i.status) === "pending").length;
      const resolvedCount = items.filter(i => ["returned", "claimed"].includes(normalizeStatus(i.status))).length;

      banner.innerHTML = `
        <div class="admin-bar">
          <div class="admin-bar-left">
            <span class="admin-bar-title">🛡️ Admin Command Bar</span>
            <div class="admin-stats">
              <span>Total: ${items.length}</span>
              <span>Active Lost: ${lostCount}</span>
              <span>Active Found: ${foundCount}</span>
              <span>Pending Approvals: ${pendingCount}</span>
              <span>Resolved: ${resolvedCount}</span>
            </div>
          </div>
          <div class="admin-bar-actions">
            <button type="button" class="btn-admin-action" onclick="openBroadcastModal()">📢 Broadcast Notice</button>
            <button type="button" class="btn-admin-action" onclick="exportAuditReportCSV()">📥 Export CSV Log</button>
            <button type="button" class="btn-admin-action" onclick="switchMainView('dashboard'); switchDashTab('admin-overview');">📊 Full Console</button>
          </div>
        </div>
      `;
    } else {
      banner.innerHTML = "";
    }
  }

  function renderCampusBroadcast() {
    const area = document.getElementById("campusBroadcastArea");
    if (!area) return;
    // Broadcast text is public, non-sensitive content served from
    // metadata/broadcast (read-only for everyone, admin-only writes).
    const broadcast = getBroadcast();
    const user = getCurrentUser();
    const isAdmin = isAdminSession(user);

    if (broadcast && broadcast.text) {
      area.innerHTML = `
        <div class="campus-broadcast-banner">
          <div class="broadcast-content">
            <span>📢</span>
            <span>${escapeHtml(broadcast.text)}</span>
          </div>
          ${isAdmin ? `<button type="button" class="broadcast-remove-btn" onclick="clearBroadcastNotice()">✕ Remove Notice</button>` : ""}
        </div>
      `;
    } else {
      area.innerHTML = "";
    }
  }

  function openBroadcastModal() {
    if (!isAdminSession(getCurrentUser())) return;
    const current = getBroadcast();
    document.getElementById("broadcastInputText").value = current ? current.text : "";
    document.getElementById("broadcastOverlay").classList.add("open");
  }
  function closeBroadcastModal(e) {
    if (e && e.target.id !== "broadcastOverlay") return;
    document.getElementById("broadcastOverlay").classList.remove("open");
  }
  async function handleBroadcastSubmit(e) {
    e.preventDefault();
    if (!isAdminSession(getCurrentUser())) {
      showToast("Administrator access required.");
      return false;
    }
    const text = document.getElementById("broadcastInputText").value.trim().slice(0, 500);
    if (!text) return false;
    try {
      await saveBroadcastToFirestore(text);
      cachedBroadcast = { text };
      closeBroadcastModal();
      renderCampusBroadcast();
      addLog("Admin updated campus broadcast bulletin");
      showToast("Campus broadcast published! 📢");
    } catch (err) {
      showToast("Could not publish the notice. Please try again.");
      console.warn("Broadcast update failed:", err.message);
    }
    return false;
  }
  async function clearBroadcastNotice() {
    if (!isAdminSession(getCurrentUser())) return;
    try {
      await saveBroadcastToFirestore("");
      cachedBroadcast = { text: "" };
      closeBroadcastModal();
      renderCampusBroadcast();
      showToast("Broadcast cleared.");
    } catch (err) {
      showToast("Could not clear the notice.");
    }
  }

  /* =========================================================================
   * PUBLIC BOARD RENDERING
   * ========================================================================= */
  function populateCategoryDropdowns() {
    const cats = getCategories();
    const filterSel = document.getElementById("categoryFilter");
    const repSel = document.getElementById("repCategory");
    const editSel = document.getElementById("aEditCategory");

    if (filterSel) {
      filterSel.innerHTML = `<option value="all">All Categories</option>` + 
        cats.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");
    }
    if (repSel) {
      repSel.innerHTML = cats.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");
    }
    if (editSel) {
      editSel.innerHTML = cats.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");
    }
  }

  function setBoardFilter(f) {
    boardFilter = f;
    document.querySelectorAll(".filter-btn").forEach(btn => {
      btn.classList.toggle("active", btn.dataset.filter === f);
    });
    renderBoard();
  }

  function renderBoard() {
    const grid = document.getElementById("boardGrid");
    if (!grid) return;
    const q = (document.getElementById("searchInput")?.value || "").trim().toLowerCase();
    const cat = document.getElementById("categoryFilter")?.value || "all";
    const items = getItems();
    const user = getCurrentUser();
    const isAdmin = isAdminSession(user);

    // Filtering logic. Statuses are normalized because legacy rows may still
    // use the old capitalised values.
    const filtered = items.filter(it => {
      const st = normalizeStatus(it.status);
      // Pending and Rejected items require faculty/staff action and do not appear on public corkboard
      if (st === "pending" || st === "rejected") return false;

      let matchesType = true;
      if (boardFilter === "lost") matchesType = it.type === "lost" && st !== "returned";
      else if (boardFilter === "found") matchesType = it.type === "found" && st !== "returned";
      else if (boardFilter === "custody") matchesType = Boolean(it.isCustody) && st !== "returned";
      else if (boardFilter === "claimed") matchesType = st === "claimed" || st === "returned";

      const matchesCat = (cat === "all") || (it.category === cat);
      const matchesQuery = !q ||
        String(it.title || "").toLowerCase().includes(q) ||
        String(it.location || "").toLowerCase().includes(q) ||
        String(it.category || "").toLowerCase().includes(q) ||
        String(it.desc || "").toLowerCase().includes(q) ||
        String(it.custodyLocation || "").toLowerCase().includes(q);

      return matchesType && matchesCat && matchesQuery;
    });

    if (filtered.length === 0) {
      grid.innerHTML = `<div class="empty">No matching items found on the board. Try another keyword or category!</div>`;
      return;
    }

    // Sort: pinned items first, then newest server timestamp.
    filtered.sort((a, b) => {
      if (a.isPinned && !b.isPinned) return -1;
      if (!a.isPinned && b.isPinned) return 1;
      return toJsDate(b.createdAt) - toJsDate(a.createdAt);
    });

    grid.innerHTML = filtered.map(it => {
      const st = normalizeStatus(it.status);
      const isReturned = st === "returned";
      const isClaimed = st === "claimed";
      const pinTag = it.isPinned ? `<span class="tag pinned">📌 Pinned</span>` : "";

      let statusTag = `<span class="tag ${it.type === "found" ? "found" : "lost"}">${it.type === "lost" ? "Lost" : "Found"}</span>`;
      if (isReturned) statusTag = `<span class="tag returned">✔️ Returned</span>`;
      else if (isClaimed) statusTag = `<span class="tag claimed">🤝 Claimed</span>`;

      const custodyTag = it.isCustody ? `<span class="tag custody">🏛️ Dept Custody</span>` : "";
      const staffTag = (!it.isCustody && it.isStaffVerified) ? `<span class="tag faculty">🎓 Staff Turn-In</span>` : "";

      const image = safeImageUrl(it.image);
      const imageBox = image ? `
        <div class="card-image-wrap">
          <img src="${escapeHtml(image)}" alt="${escapeHtml(it.title)}">
        </div>
      ` : "";

      const custodyLine = it.isCustody && it.custodyLocation ? `
        <div class="card-custody-info">
          <span>🏛️ Held at:</span>
          <span>${escapeHtml(String(it.custodyLocation).split(",")[0])}</span>
        </div>
      ` : "";

      const id = safeDocId(it.id);
      const adminToolbar = (isAdmin && id) ? `
        <div class="card-admin-toolbar" onclick="event.stopPropagation()">
          <button type="button" class="card-admin-btn pin" onclick="togglePinItem(decodeURIComponent('${handlerArg(id)}'))" title="${it.isPinned ? 'Unpin' : 'Pin to top'}">📌</button>
          <button type="button" class="card-admin-btn edit" onclick="openAdminEditModal(decodeURIComponent('${handlerArg(id)}'))" title="Admin Edit">✏️</button>
          <button type="button" class="card-admin-btn del" onclick="deleteItemDirect(event, decodeURIComponent('${handlerArg(id)}'))" title="Delete">✕</button>
        </div>
      ` : "";

      return `
        <div class="card ${isClaimed || isReturned ? 'is-claimed' : ''} ${it.isPinned ? 'is-pinned' : ''}" onclick="openDetail(decodeURIComponent('${handlerArg(id)}'))">
          ${adminToolbar}
          <span class="pin">📌</span>
          ${imageBox}
          <div class="card-top">
            <div class="tags-wrapper">
              ${pinTag}
              ${statusTag}
              ${custodyTag}
              ${staffTag}
            </div>
            <span class="card-date">${escapeHtml(itemDateLabel(it))}</span>
          </div>
          <h3 class="card-title display">${escapeHtml(it.title)}</h3>
          <p class="card-category">${escapeHtml(it.category)}</p>
          <div class="card-location">📍 ${escapeHtml(it.location)}</div>
          ${custodyLine}
        </div>
      `;
    }).join("");
  }

  /* =========================================================================
   * ITEM DETAIL MODAL
   * ========================================================================= */
  async function openDetail(rawId) {
    const id = String(rawId || "");
    const item = getItems().find(i => String(i.id) === id);
    if (!item) return;

    const user = getCurrentUser();
    // Ownership is based on the authenticated UID recorded by createItem, never
    // on a user-supplied contact address (which was spoofable).
    const isOwner = Boolean(user && item.reporterUid && item.reporterUid === user.uid);
    const isAdmin = isAdminSession(user);
    const isFaculty = Boolean(user && user.role === "faculty");
    const isStudent = Boolean(user && user.role === "student");
    const canSeeContact = isOwner || isAdmin || isFaculty;

    const st = normalizeStatus(item.status);
    const isReturned = st === "returned";
    const isClaimed = st === "claimed";
    const idArg = handlerArg(safeDocId(item.id));

    // Actions based on role & permissions
    let actionButtons = "";
    if (isAdmin) {
      actionButtons = `
        <div class="detail-actions">
          <button class="btn-action-primary" onclick="toggleItemStatus(decodeURIComponent('${idArg}'))">
            ${isReturned ? "🔄 Reopen Item" : "✔️ Mark as Returned"}
          </button>
          <button class="btn-action-secondary" onclick="togglePinItem(decodeURIComponent('${idArg}')); openDetail(decodeURIComponent('${idArg}'));">
            ${item.isPinned ? "📌 Unpin" : "📌 Pin to Top"}
          </button>
          <button class="btn-action-secondary" onclick="openAdminEditModal(decodeURIComponent('${idArg}'))">
            ✏️ Edit Report
          </button>
          <button class="btn-action-danger" onclick="deleteItemDirect(null, decodeURIComponent('${idArg}'))">
            🗑️ Delete (Admin)
          </button>
        </div>
      `;
    } else if (isFaculty) {
      actionButtons = `
        <div class="detail-actions">
          <button class="btn-action-primary" onclick="toggleItemStatus(decodeURIComponent('${idArg}'))">
            ${isReturned ? "🔄 Reopen" : "✔️ Mark as Returned"}
          </button>
          ${!item.isCustody ? `
            <button class="btn-action-secondary" onclick="quickTakeCustody(decodeURIComponent('${idArg}'))">
              🏛️ Take into Dept Custody
            </button>
          ` : ""}
          ${!item.isStaffVerified ? `
            <button class="btn-action-secondary" onclick="verifyReportByStaff(decodeURIComponent('${idArg}'))">
              🎓 Verify Report
            </button>
          ` : ""}
        </div>
      `;
    } else if (isStudent) {
      if (isOwner) {
        actionButtons = `
          <div class="detail-actions">
            <button class="btn-action-secondary" onclick="openStudentEditModal(decodeURIComponent('${idArg}'))">
              ✏️ Edit My Report
            </button>
            <button class="btn-action-primary" onclick="toggleItemStatus(decodeURIComponent('${idArg}'))">
              ${isReturned ? "🔄 Reopen My Report" : "✔️ Mark as Returned"}
            </button>
            <button class="btn-action-danger" onclick="deleteItemDirect(null, decodeURIComponent('${idArg}'))">
              🗑️ Delete My Report
            </button>
          </div>
        `;
      } else if (!isClaimed && !isReturned && st === "approved") {
        actionButtons = `
          <div class="detail-actions">
            <button class="btn-action-claim" onclick="openClaimModal(decodeURIComponent('${idArg}'))">
              🤝 This is mine! Send Claim Request
            </button>
          </div>
        `;
      }
    } else {
      // Guest
      if (!isClaimed && !isReturned) {
        actionButtons = `
          <div class="detail-actions">
            <a href="login.html" class="btn-action-claim" style="text-decoration: none;">
              Sign In to Submit Claim Request
            </a>
          </div>
        `;
      }
    }

    const image = safeImageUrl(item.image);
    const imageHtml = image ? `
      <div style="max-height: 220px; overflow: hidden; border-radius: 4px; margin-bottom: 14px;">
        <img src="${escapeHtml(image)}" alt="" style="width: 100%; height: 220px; object-fit: cover;">
      </div>
    ` : "";

    const custodyBox = item.isCustody ? `
      <div class="custody-box">
        <div class="custody-box-title">🏛️ Official Campus Department Custody</div>
        <div class="custody-box-row"><strong>📍 Pickup Office:</strong> ${escapeHtml(item.custodyLocation || "Campus Office")}</div>
        <div class="custody-box-row"><strong>⏰ Office Hours:</strong> ${escapeHtml(item.custodyHours || "Mon-Fri 9:00 AM - 4:00 PM")}</div>
        <div class="custody-box-row"><strong>📋 Claim Procedure:</strong> ${escapeHtml(item.custodyNotes || "Present student ID to verify.")}</div>
      </div>
    ` : "";

    // Contact details now live in items/{id}/private/contact and are only
    // loaded for the reporter and staff. Other students never see them.
    const contactBox = canSeeContact ? `
      <div class="contact-card-box" id="detailContactBox" style="background: #F7F2E7; padding: 12px 14px; border-radius: 4px; border: 1px solid var(--border); margin-top: 10px;">
        <div>
          <div style="font-size: 11px; font-weight: 700; color: var(--muted); text-transform: uppercase;">Contact Info (private)</div>
          <div id="detailContactValue" style="font-size: 14px; font-weight: 600; color: var(--ink); margin-top: 2px;">Loading…</div>
        </div>
      </div>
    ` : `
      <div style="font-size: 12px; color: var(--muted); margin-top: 10px;">
        🔒 Reporter contact details are shared privately with faculty/staff only.
      </div>
    `;

    document.getElementById("detailContent").innerHTML = `
      ${imageHtml}
      <div class="tags-wrapper" style="margin-bottom: 8px;">
        <span class="tag ${item.type === "found" ? "found" : "lost"}">${item.type === "lost" ? "Lost Report" : "Found Report"}</span>
        <span class="tag ${escapeHtml(st)}">${escapeHtml(statusLabel(st))}</span>
        ${item.isCustody ? `<span class="tag custody">🏛️ In Dept Custody</span>` : ""}
        ${item.isStaffVerified ? `<span class="tag faculty">🎓 Staff Verified</span>` : ""}
      </div>
      <h2 class="display">${escapeHtml(item.title)}</h2>
      <div class="meta" style="font-size: 13px; color: var(--muted); margin: 6px 0 12px;">
        Category: <strong>${escapeHtml(item.category)}</strong> &middot; Reported: ${escapeHtml(itemDateLabel(item))} by ${escapeHtml(item.reporterName || item.posterName || "Campus Member")}
      </div>
      <div class="loc" style="font-size: 14px; margin-bottom: 12px;">📍 Location: <strong>${escapeHtml(item.location)}</strong></div>
      <p style="font-size: 14px; line-height: 1.6; margin-bottom: 14px;">${escapeHtml(item.desc || "No extra description provided.")}</p>

      ${custodyBox}
      ${contactBox}
      ${actionButtons}
    `;

    document.getElementById("detailOverlay").classList.add("open");

    if (canSeeContact) {
      try {
        const contact = await getReporterContact(id);
        const valueEl = document.getElementById("detailContactValue");
        if (valueEl) valueEl.textContent = contact || "Not provided";
      } catch (e) {
        const valueEl = document.getElementById("detailContactValue");
        if (valueEl) valueEl.textContent = "Unavailable";
      }
    }
  }

  function closeDetail(e) {
    if (e && e.target.id !== "detailOverlay") return;
    document.getElementById("detailOverlay").classList.remove("open");
  }

  /* =========================================================================
   * ITEM ACTIONS (Pin, Status, Custody, Delete)
   * ========================================================================= */
  async function togglePinItem(rawId) {
    const id = safeDocId(rawId);
    const it = getItems().find(i => String(i.id) === id);
    if (!it || !isAdminSession(getCurrentUser())) return;
    try {
      await updateItem(id, { isPinned: !it.isPinned });
      renderBoard();
      showToast(it.isPinned ? "Unpinned item." : "📌 Pinned item to top of board.");
    } catch (err) {
      showToast("Could not update the pin. Please try again.");
    }
  }

  async function toggleItemStatus(rawId) {
    const id = safeDocId(rawId);
    const it = getItems().find(i => String(i.id) === id);
    if (!it) return;
    const user = getCurrentUser();
    const isOwner = user && it.reporterUid === user.uid;
    if (!isStaffSession(user) && !isOwner) return;

    const reopening = normalizeStatus(it.status) === "returned";
    try {
      await updateItem(id, { status: reopening ? "approved" : "returned" });
      showToast(reopening ? "Report reopened on the board." : "🎉 Item successfully marked as Returned!");
      addLog(`Item ${id} (${it.title}) marked as ${reopening ? "Approved" : "Returned"}`);
      if (!reopening && it.reporterUid) {
        createNotification(it.reporterUid, `Your report "${it.title}" is now marked as Returned.`);
      }
      renderBoard();
      if (document.getElementById("detailOverlay").classList.contains("open")) openDetail(id);
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
    } catch (err) {
      showToast("Could not update the item status.");
      console.warn("Status update failed:", err.message);
    }
  }

  async function deleteItemDirect(e, rawId) {
    if (e) e.stopPropagation();
    const id = safeDocId(rawId);
    const it = getItems().find(i => String(i.id) === id);
    if (!it) return;
    const user = getCurrentUser();
    const isOwner = user && it.reporterUid === user.uid;
    if (!isAdminSession(user) && !isOwner) return;
    if (!confirm("Are you sure you want to permanently delete this report?")) return;
    try {
      await deleteItem(id);
      closeDetail();
      renderBoard();
      renderAdminBanner();
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
      showToast("Report permanently deleted.");
      addLog(`Deleted item report ${id}`);
    } catch (err) {
      showToast("Could not delete the report.");
      console.warn("Delete failed:", err.message);
    }
  }

  async function quickTakeCustody(rawId) {
    const id = safeDocId(rawId);
    if (!isStaffSession(getCurrentUser())) return;
    const office = prompt("Enter Office / Room for Custody Storage:", "Science Library Front Desk, Room 101");
    if (!office) return;
    const it = getItems().find(i => String(i.id) === id);
    if (!it) return;
    try {
      await updateItem(id, {
        isCustody: true,
        isStaffVerified: true,
        custodyLocation: String(office).slice(0, 160),
        custodyHours: "Mon-Fri 9:00 AM - 4:00 PM",
        custodyNotes: "Present valid university ID to claim."
      });
      renderBoard();
      openDetail(id);
      showToast("Registered under Department Custody! 🏛️");
      addLog(`Item ${id} taken into custody at ${office}`);
    } catch (err) {
      showToast("Could not register custody.");
    }
  }

  async function verifyReportByStaff(rawId) {
    const id = safeDocId(rawId);
    if (!isStaffSession(getCurrentUser())) return;
    const it = getItems().find(i => String(i.id) === id);
    if (!it) return;
    try {
      await updateItem(id, { isStaffVerified: true, status: "approved" });
      renderBoard();
      openDetail(id);
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
      showToast("Report verified & approved! 🎓");
      addLog(`Faculty verified item ${id}`);
      if (it.reporterUid) {
        createNotification(it.reporterUid, `Your report for "${it.title}" was verified and approved by faculty! It is now live on the public board.`);
      }
    } catch (err) {
      showToast("Could not verify the report.");
    }
  }

  async function rejectReportByStaff(rawId) {
    const id = safeDocId(rawId);
    if (!isStaffSession(getCurrentUser())) return;
    if (!confirm("Are you sure you want to reject this report?")) return;
    const it = getItems().find(i => String(i.id) === id);
    if (!it) return;
    try {
      await updateItem(id, { isStaffVerified: true, status: "rejected" });
      renderBoard();
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
      showToast("Report marked as Rejected. ❌");
      addLog(`Faculty/Staff rejected item report ${id}`);
      if (it.reporterUid) {
        createNotification(it.reporterUid, `Your report for "${it.title}" was rejected by faculty/admin. Contact student support for assistance.`);
      }
    } catch (err) {
      showToast("Could not reject the report.");
    }
  }

  /* =========================================================================
   * REPORT ITEM FORM & PHOTO UPLOAD
   * ========================================================================= */
  function openReportModal() {
    const user = getCurrentUser();
    if (!user) {
      showToast("Please sign in or create an account to post an item.");
      setTimeout(() => window.location.href = "login.html", 800);
      return;
    }

    const facCustody = document.getElementById("repFacultyCustody");
    if (facCustody) {
      facCustody.style.display = (user.role === "faculty" || user.role === "admin") ? "block" : "none";
    }

    const contactInput = document.getElementById("repContact");
    if (contactInput && !contactInput.value) {
      contactInput.value = user.email;
    }

    document.getElementById("reportOverlay").classList.add("open");
  }

  function closeReportModal(e) {
    if (e && e.target.id !== "reportOverlay") return;
    document.getElementById("reportOverlay").classList.remove("open");
    document.getElementById("reportForm").reset();
    pendingPhotoFile = null;
    if (pendingPhotoPreviewUrl) {
      URL.revokeObjectURL(pendingPhotoPreviewUrl);
      pendingPhotoPreviewUrl = "";
    }
    document.getElementById("photoPreviewWrap").style.display = "none";
    setReportType("lost");
  }

  function setReportType(type) {
    formReportType = type;
    const btnLost = document.getElementById("btnTypeLost");
    const btnFound = document.getElementById("btnTypeFound");
    const locLabel = document.getElementById("repLocationLabel");

    if (type === "lost") {
      btnLost.className = "lost-active";
      btnFound.className = "found-inactive";
      locLabel.textContent = "Where was it lost?";
    } else {
      btnLost.className = "lost-inactive";
      btnFound.className = "found-active";
      locLabel.textContent = "Where was it found?";
    }
  }

  function handlePhotoUpload(input) {
    if (!input.files || !input.files[0]) return;
    const file = input.files[0];

    // Only a local object URL is used for the preview. The image itself is
    // compressed/re-encoded and uploaded to Storage on submit.
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (!allowed.includes(file.type)) {
      showToast("Only JPEG, PNG, or WebP images are allowed.");
      input.value = "";
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      showToast("Image is too large. Maximum input size is 10 MB.");
      input.value = "";
      return;
    }

    pendingPhotoFile = file;
    if (pendingPhotoPreviewUrl) URL.revokeObjectURL(pendingPhotoPreviewUrl);
    pendingPhotoPreviewUrl = URL.createObjectURL(file);
    document.getElementById("photoPreviewImg").src = pendingPhotoPreviewUrl;
    document.getElementById("photoPreviewWrap").style.display = "block";
  }

  async function handleReportSubmit(e) {
    e.preventDefault();
    const user = getCurrentUser();
    if (!user) {
      showToast("Please sign in again.");
      return false;
    }
    const title = document.getElementById("repTitle").value.trim().slice(0, 100);
    const category = document.getElementById("repCategory").value;
    const location = document.getElementById("repLocation").value.trim().slice(0, 160);
    const desc = document.getElementById("repDesc").value.trim().slice(0, 1000);
    const contact = document.getElementById("repContact").value.trim().slice(0, 160);

    if (!title || !location || !contact) return false;

    const isFacultyStaff = user.role === "faculty";
    const isAdmin = user.role === "admin";
    const takesCustody = isFacultyStaff && document.getElementById("repStaffCustodyCheck")?.checked;
    const custodyOffice = takesCustody ? (document.getElementById("repCustodyOffice")?.value.trim().slice(0, 160) || "Department Front Desk") : "";
    const custodyHours = takesCustody ? (document.getElementById("repCustodyHours")?.value.trim().slice(0, 160) || "Mon-Fri 9:00 AM - 4:00 PM") : "";

    const itemPayload = {
      type: formReportType,
      title,
      category: String(category || "Other Valuables").slice(0, 80),
      location,
      desc,
      image: "",
      // contact is moved into items/{id}/private/contact by createItem.
      contact,
      reporterName: user.name || "Campus Member",
      reporterFirstName: String(user.name || "Campus Member").split(" ")[0],
      reporterDepartment: user.department || "",
      isCustody: Boolean(takesCustody),
      custodyLocation: custodyOffice,
      custodyHours: custodyHours,
      custodyNotes: takesCustody ? "Bring student ID card to collect." : "",
      isPinned: false,
      isStaffVerified: Boolean(isAdmin || isFacultyStaff)
    };

    // Offline path: queue a text-only report so nothing is lost. Photos cannot
    // be stored in IndexedDB safely/size-limited here, so an offline report
    // with an attached photo is refused instead of silently dropping the photo.
    if (!navigator.onLine) {
      if (pendingPhotoFile) {
        showToast("Photos need a connection. Remove the photo to save this report offline, or reconnect and submit.");
        return false;
      }
      await queueReportForLater(itemPayload);
      return false;
    }

    // Photo is compressed, EXIF-stripped, and stored as a base64 data URL
    // directly in the Firestore item document. No Firebase Storage is used.
    if (pendingPhotoFile) {
      try {
        itemPayload.image = await uploadPhotoToFirebase(pendingPhotoFile);
      } catch (err) {
        showToast(err.message || "Photo upload failed. Please try again.");
        return false;
      }
    }

    try {
      const newId = await createItem(itemPayload);

      // createItem always writes status "pending" and isStaffVerified false so
      // the create rule can never be used to self-approve. Staff/admin reports
      // are approved in a separate, rule-checked update.
      if (isAdmin || isFacultyStaff) {
        await updateItem(newId, { status: "approved", isStaffVerified: true });
      }

      const initialStatus = (isAdmin || isFacultyStaff) ? "approved" : "pending";

      addLog(`${user.name} reported ${formReportType} item: "${title}" (Status: ${initialStatus})`);

      if (initialStatus === "pending") {
        createNotification(user.uid, `Your ${formReportType} report for "${title}" was submitted for Faculty/Staff verification.`);
      } else {
        createNotification(user.uid, `Your ${formReportType} report for "${title}" has been published to the board.`);
      }

      // Real-Time Match Check (opposite report type with matching category/keyword)
      const oppositeType = formReportType === "lost" ? "found" : "lost";
      const matchedOpposite = getItems().find(i =>
        i.type === oppositeType &&
        normalizeStatus(i.status) === "approved" &&
        (i.category === category ||
         title.toLowerCase().split(" ").some(w => w.length > 3 && String(i.title || "").toLowerCase().includes(w)))
      );

      if (matchedOpposite) {
        createNotification(user.uid, `⚡ Real-Time Match Alert: A ${oppositeType} item ('${matchedOpposite.title}') at ${matchedOpposite.location} may match your new report!`);
      }

      closeReportModal();
      renderBoard();
      renderAdminBanner();
      renderAuthHeader();
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);

      showToast(initialStatus === "pending"
        ? "Report submitted! Awaiting Faculty / Staff verification ⏳"
        : "Report published to board successfully! 📌");
    } catch (err) {
      console.warn("Report submission failed:", err.message);
      if (typeof isNetworkError === "function" && isNetworkError(err) && !itemPayload.image) {
        const queued = await queueReportForLater(itemPayload);
        if (queued) return false;
      }
      showToast("Could not submit your report. Please try again.");
    }
    return false;
  }

  /* =========================================================================
   * CLAIM WORKFLOW (Student sends private proof)
   * ========================================================================= */
  function openClaimModal(rawItemId) {
    const user = getCurrentUser();
    if (!user) {
      showToast("Please sign in to submit a claim request.");
      setTimeout(() => window.location.href = "login.html", 800);
      return;
    }

    const itemId = safeDocId(rawItemId);
    const it = getItems().find(i => String(i.id) === itemId);
    if (!it) return;
    if (it.reporterUid === user.uid) {
      showToast("You cannot claim your own report.");
      return;
    }
    if (normalizeStatus(it.status) !== "approved") {
      showToast("This item is not open for claims.");
      return;
    }
    const already = getClaims().some(c =>
      String(c.itemId) === itemId &&
      c.claimantUid === user.uid &&
      String(c.status || "").toLowerCase() === "pending"
    );
    if (already) {
      showToast("You already have a pending claim for this item.");
      return;
    }

    document.getElementById("claimItemId").value = itemId;
    document.getElementById("claimItemTitleDisplay").textContent = it.title;
    document.getElementById("claimContact").value = user.email;
    document.getElementById("claimProof").value = "";
    document.getElementById("claimOverlay").classList.add("open");
  }

  function closeClaimModal(e) {
    if (e && e.target.id !== "claimOverlay") return;
    document.getElementById("claimOverlay").classList.remove("open");
  }

  async function handleClaimSubmit(e) {
    e.preventDefault();
    const user = getCurrentUser();
    if (!user) return false;
    const itemId = safeDocId(document.getElementById("claimItemId").value);
    const proof = document.getElementById("claimProof").value.trim().slice(0, 1000);
    const contact = document.getElementById("claimContact").value.trim().slice(0, 160);

    const it = getItems().find(i => String(i.id) === itemId);
    if (!it || !proof) return false;

    try {
      // createClaim batches claims/{id} and claims/{id}/private/proof. The proof
      // text is never added to the public claim document or the local cache.
      await createClaim({
        itemId,
        itemTitle: it.title,
        contact,
        proofDetails: proof
      });

      createNotification(user.uid, `Claim request submitted for "${it.title}". Faculty/Staff will review your proof.`);
      // The reporter notification is written by the onClaimWritten Cloud
      // Function. A student cannot (and should not) write to another user's
      // notifications directly.

      addLog(`${user.name} submitted claim request for item ${itemId}`);

      closeClaimModal();
      closeDetail();
      showToast("Claim request sent! Faculty / staff will verify your proof. 📨");
      renderAuthHeader();
    } catch (err) {
      console.warn("Claim submission failed:", err.message);
      showToast("Could not submit the claim. Please try again.");
    }
    return false;
  }

  async function openReviewClaimModal(rawClaimId) {
    if (!isStaffSession(getCurrentUser())) return;
    const claimId = safeDocId(rawClaimId);
    const cl = getClaims().find(c => String(c.id) === claimId);
    if (!cl) return;

    const idArg = handlerArg(claimId);
    document.getElementById("reviewClaimContent").innerHTML = `
      <div style="background: #FAF7F0; padding: 14px; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 16px;">
        <div style="font-size: 15px; font-weight: 700; color: var(--ink); margin-bottom: 4px;">${escapeHtml(cl.itemTitle)}</div>
        <div style="font-size: 12px; color: var(--muted);">Claimant: <strong>${escapeHtml(cl.claimantName)}</strong> (${escapeHtml(cl.claimantEmail)})</div>
        <div style="font-size: 12px; color: var(--muted); margin-top: 2px;">Submitted: ${escapeHtml(formatDateTime(cl.createdAt))}</div>
      </div>

      <div style="margin-bottom: 16px;">
        <div style="font-size: 12px; font-weight: 700; color: var(--muted); text-transform: uppercase;">Private Proof of Ownership</div>
        <div id="reviewClaimProof" style="background: #FFF; border: 1px solid var(--border); padding: 12px; border-radius: 4px; margin-top: 6px; font-size: 13px; line-height: 1.5; color: var(--ink);">
          Loading private proof…
        </div>
      </div>

      <div class="modal-action-row" style="display: flex; gap: 8px;">
        <button type="button" class="btn-action-primary" style="flex: 1; padding: 10px;" onclick="resolveClaim(decodeURIComponent('${idArg}'), 'Approved')">
          ✅ Confirm Ownership &amp; Approve
        </button>
        <button type="button" class="btn-action-danger" style="flex: 1; padding: 10px;" onclick="resolveClaim(decodeURIComponent('${idArg}'), 'Rejected')">
          ❌ Reject Claim
        </button>
      </div>
    `;

    document.getElementById("reviewClaimOverlay").classList.add("open");

    try {
      const proof = await getClaimProof(claimId);
      const proofEl = document.getElementById("reviewClaimProof");
      if (proofEl) proofEl.textContent = proof && proof.proofDetails ? proof.proofDetails : "No proof on file.";
    } catch (err) {
      const proofEl = document.getElementById("reviewClaimProof");
      if (proofEl) proofEl.textContent = "Private proof could not be loaded.";
    }
  }

  function closeReviewClaimModal(e) {
    if (e && e.target.id !== "reviewClaimOverlay") return;
    document.getElementById("reviewClaimOverlay").classList.remove("open");
  }

  async function resolveClaim(rawClaimId, resolution) {
    if (!isStaffSession(getCurrentUser())) return;
    const claimId = safeDocId(rawClaimId);
    const cl = getClaims().find(c => String(c.id) === claimId);
    if (!cl) return;
    if (resolution !== "Approved" && resolution !== "Rejected") return;

    try {
      await resolveClaimInFirestore(claimId, resolution, String(cl.itemId || ""));
      addLog(`Claim ${claimId} was ${resolution} by staff`);

      if (cl.claimantUid) {
        createNotification(cl.claimantUid, resolution === "Approved"
          ? `Your claim for "${cl.itemTitle}" was approved. Contact the finder/faculty to arrange pickup.`
          : `Your claim for "${cl.itemTitle}" was not approved. Contact student support if you believe this is an error.`);
      }

      closeReviewClaimModal();
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
      renderBoard();
      showToast(`Claim has been ${resolution.toLowerCase()}.`);
    } catch (err) {
      console.warn("Claim resolution failed:", err.message);
      showToast("Could not update the claim.");
    }
  }

  /* =========================================================================
   * ADMIN EDIT REPORT MODAL
   * ========================================================================= */
  async function openAdminEditModal(rawId) {
    if (!isAdminSession(getCurrentUser())) return;
    const id = safeDocId(rawId);
    const it = getItems().find(i => String(i.id) === id);
    if (!it) return;

    document.getElementById("aEditId").value = id;
    document.getElementById("aEditTitle").value = it.title || "";
    document.getElementById("aEditCategory").value = it.category || "";
    document.getElementById("aEditLocation").value = it.location || "";
    document.getElementById("aEditDesc").value = it.desc || "";
    document.getElementById("aEditStatus").value = normalizeStatus(it.status);
    // Never trust a cached contact value: load the private document.
    document.getElementById("aEditContact").value = "";
    document.getElementById("adminEditOverlay").classList.add("open");
    try {
      const contact = await getReporterContact(id);
      document.getElementById("aEditContact").value = contact || "";
    } catch (e) {}
  }

  function closeAdminEditModal(e) {
    if (e && e.target.id !== "adminEditOverlay") return;
    document.getElementById("adminEditOverlay").classList.remove("open");
  }

  async function handleAdminEditSubmit(e) {
    e.preventDefault();
    if (!isAdminSession(getCurrentUser())) return false;
    const id = safeDocId(document.getElementById("aEditId").value);
    const it = getItems().find(i => String(i.id) === id);
    if (!it) return false;

    try {
      await updateItem(id, {
        title: document.getElementById("aEditTitle").value.trim().slice(0, 100),
        category: document.getElementById("aEditCategory").value,
        location: document.getElementById("aEditLocation").value.trim().slice(0, 160),
        desc: document.getElementById("aEditDesc").value.trim().slice(0, 1000),
        status: normalizeStatus(document.getElementById("aEditStatus").value)
      });
      const contact = document.getElementById("aEditContact").value.trim().slice(0, 160);
      await updateItemContact(id, contact);

      closeAdminEditModal();
      renderBoard();
      renderAdminBanner();
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
      showToast("Report updated by Admin.");
      addLog(`Admin updated item report ${id}`);
    } catch (err) {
      showToast("Could not update the report.");
    }
    return false;
  }

  /* =========================================================================
   * ROLE-BASED DASHBOARD LOGIC
   * ========================================================================= */
  function initDashboard() {
    const user = getCurrentUser();
    if (!user) return;

    // Sidebar Profile Card
    document.getElementById("dashUserCard").innerHTML = `
      <div class="dash-user-name">${escapeHtml(user.name)}</div>
      <div class="dash-user-email">${escapeHtml(user.email)}</div>
      <span class="role-pill">${user.role.toUpperCase()}</span>
    `;

    const nav = document.getElementById("dashNav");
    if (!nav.dataset.bound) {
      nav.addEventListener("click", (event) => {
        const button = event.target.closest("[data-dash-tab]");
        if (!button) return;
        switchDashTab(button.dataset.dashTab);
      });
      nav.dataset.bound = "1";
    }

    if (user.role === "student") {
      nav.innerHTML = `
        <li class="dash-nav-item"><button id="btnTab_my-lost" onclick="switchDashTab('my-lost')">📦 My Lost Items</button></li>
        <li class="dash-nav-item"><button id="btnTab_my-found" onclick="switchDashTab('my-found')">🎁 My Found Items</button></li>
        <li class="dash-nav-item"><button id="btnTab_search-items" onclick="switchDashTab('search-items')">🔍 Search Items</button></li>
        <li class="dash-nav-item"><button id="btnTab_claims" onclick="switchDashTab('claims')">🤝 Claim Requests</button></li>
        <li class="dash-nav-item"><button id="btnTab_messages" data-dash-tab="messages">💬 Messages <span class="nav-unread-badge" id="messagesUnreadBadge" hidden></span></button></li>
        <li class="dash-nav-item"><button id="btnTab_notifs" onclick="switchDashTab('notifs')">🔔 Notifications</button></li>
        <li class="dash-nav-item"><button id="btnTab_notif-settings" data-dash-tab="notif-settings">⚙️ Notification Settings</button></li>
        <li class="dash-nav-item"><button id="btnTab_profile" onclick="switchDashTab('profile')">👤 My Profile</button></li>
        <li class="dash-nav-item dash-nav-divider" style="margin-top: 10px; border-top: 1px dashed var(--border); padding-top: 8px;"><button onclick="switchMainView('board')">📌 Public Corkboard</button></li>
      `;
      switchDashTab(activeDashTab || "my-lost");
    } else if (user.role === "faculty") {
      nav.innerHTML = `
        <li class="dash-nav-item"><button id="btnTab_fac-lost" onclick="switchDashTab('fac-lost')">📋 All Lost Items</button></li>
        <li class="dash-nav-item"><button id="btnTab_fac-found" onclick="switchDashTab('fac-found')">🔍 All Found Items</button></li>
        <li class="dash-nav-item"><button id="btnTab_fac-pending" onclick="switchDashTab('fac-pending')">⏳ Pending Verification</button></li>
        <li class="dash-nav-item"><button id="btnTab_fac-claims" onclick="switchDashTab('fac-claims')">🤝 Claim Requests</button></li>
        <li class="dash-nav-item"><button id="btnTab_fac-returned" onclick="switchDashTab('fac-returned')">✅ Returned Items</button></li>
        <li class="dash-nav-item"><button id="btnTab_messages" data-dash-tab="messages">💬 Messages <span class="nav-unread-badge" id="messagesUnreadBadge" hidden></span></button></li>
        <li class="dash-nav-item"><button id="btnTab_notif-settings" data-dash-tab="notif-settings">⚙️ Notification Settings</button></li>
        <li class="dash-nav-item"><button id="btnTab_fac-support" onclick="switchDashTab('fac-support')">💬 Student Support</button></li>
      `;
      switchDashTab(activeDashTab || "fac-pending");
    } else if (user.role === "admin") {
      nav.innerHTML = `
        <li class="dash-nav-item"><button id="btnTab_admin-overview" onclick="switchDashTab('admin-overview')">📊 Dashboard Overview</button></li>
        <li class="dash-nav-item"><button id="btnTab_admin-students" onclick="switchDashTab('admin-students')">🎓 Manage Students</button></li>
        <li class="dash-nav-item"><button id="btnTab_admin-faculty" onclick="switchDashTab('admin-faculty')">🏛️ Manage Faculty / Staff</button></li>
        <li class="dash-nav-item"><button id="btnTab_admin-lost" onclick="switchDashTab('admin-lost')">📦 Manage Lost Items</button></li>
        <li class="dash-nav-item"><button id="btnTab_admin-found" onclick="switchDashTab('admin-found')">🎁 Manage Found Items</button></li>
        <li class="dash-nav-item"><button id="btnTab_admin-claims" onclick="switchDashTab('admin-claims')">🤝 Manage Claims</button></li>
        <li class="dash-nav-item"><button id="btnTab_messages" data-dash-tab="messages">💬 Messages <span class="nav-unread-badge" id="messagesUnreadBadge" hidden></span></button></li>
        <li class="dash-nav-item"><button id="btnTab_admin-categories" onclick="switchDashTab('admin-categories')">🏷️ Manage Categories</button></li>
        <li class="dash-nav-item"><button id="btnTab_admin-complaints" onclick="switchDashTab('admin-complaints')">⚠️ Manage Complaints</button></li>
        <li class="dash-nav-item"><button id="btnTab_admin-analytics" onclick="switchDashTab('admin-analytics')">📈 Reports &amp; Analytics</button></li>
        <li class="dash-nav-item"><button id="btnTab_notif-settings" data-dash-tab="notif-settings">⚙️ Notification Settings</button></li>
        <li class="dash-nav-item"><button id="btnTab_admin-settings" onclick="switchDashTab('admin-settings')">⚙️ Website Settings</button></li>
        <li class="dash-nav-item"><button id="btnTab_admin-logs" onclick="switchDashTab('admin-logs')">📜 Activity Logs</button></li>
      `;
      switchDashTab(activeDashTab || "admin-overview");
    }
  }

  function switchDashTab(tabKey) {
    if (tabKey !== "scan-handover") stopHandoverScanner();
    if (tabKey !== "messages") closeChatThread();
    activeDashTab = tabKey;
    document.querySelectorAll(".dash-nav-item button").forEach(b => b.classList.remove("active"));
    const activeBtn = document.getElementById("btnTab_" + tabKey);
    if (activeBtn) {
      activeBtn.classList.add("active");
      try {
        activeBtn.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
      } catch (err) {}
    }
    renderDashTab(tabKey);
  }

  let dashSearchType = "all";

  function renderDashTab(tabKey) {
    const main = document.getElementById("dashMainPanel");
    const user = getCurrentUser();
    const items = getItems();
    const claims = getClaims();
    const users = getUsers();
    const cats = getCategories();
    const notifs = getNotifs();
    const logs = getLogs();

    /* ================= A. STUDENT DASHBOARD TABS ================= */
    if (tabKey === "my-lost") {
      const myLost = items.filter(i => i.type === "lost" && i.reporterUid === user.uid);
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">My Lost Items</h2>
            <p>Track your reported missing belongings, verification status, and updates.</p>
          </div>
          <button class="btn btn-report-item" onclick="openReportModal(); setReportType('lost');">+ Report Lost Item</button>
        </div>
        ${renderItemsTable(myLost, true)}
      `;
    } else if (tabKey === "my-found") {
      const myFound = items.filter(i => i.type === "found" && i.reporterUid === user.uid);
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">My Found Items</h2>
            <p>Property you discovered around campus and submitted to return to the owner.</p>
          </div>
          <button class="btn btn-report-item" onclick="openReportModal(); setReportType('found');">+ Report Found Item</button>
        </div>
        ${renderItemsTable(myFound, true)}
      `;
    } else if (tabKey === "search-items") {
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Search &amp; Filter Items</h2>
            <p>Smart campus-wide lookup by item name, category, date, and location.</p>
          </div>
          <button class="btn btn-report-item" onclick="openReportModal()">+ Report Missing Item</button>
        </div>

        <div class="dash-search-container" style="background: #FFF; border: 1px solid var(--border); border-radius: 6px; padding: 18px; margin-bottom: 24px; box-shadow: 0 2px 4px rgba(0,0,0,0.03);">
          <div class="dash-search-grid" style="display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 12px; margin-bottom: 14px;">
            <div>
              <label style="font-size: 11px; font-weight: 700; color: var(--muted); margin-bottom: 4px; display: block;">SMART KEYWORD SEARCH</label>
              <input id="dashSearchKeyword" placeholder="Search item title, brand, description..." style="width:100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 4px; font-size: 14px;" oninput="filterDashboardSearch()">
            </div>
            <div>
              <label style="font-size: 11px; font-weight: 700; color: var(--muted); margin-bottom: 4px; display: block;">CATEGORY</label>
              <select id="dashSearchCategory" style="width:100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 4px; font-size: 14px; background:#FAF7F0;" onchange="filterDashboardSearch()">
                <option value="all">All Categories</option>
                ${cats.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("")}
              </select>
            </div>
            <div>
              <label style="font-size: 11px; font-weight: 700; color: var(--muted); margin-bottom: 4px; display: block;">CAMPUS LOCATION</label>
              <input id="dashSearchLocation" placeholder="e.g. Library, Cafeteria, Gym..." style="width:100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 4px; font-size: 14px;" oninput="filterDashboardSearch()">
            </div>
          </div>
          <div class="dash-search-filters" style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="filter-btn active" id="dashFilterAll" onclick="setDashSearchType('all')">All Items</button>
            <button class="filter-btn" id="dashFilterLost" onclick="setDashSearchType('lost')">Lost Reports</button>
            <button class="filter-btn" id="dashFilterFound" onclick="setDashSearchType('found')">Found Properties</button>
            <button class="filter-btn" id="dashFilterCustody" onclick="setDashSearchType('custody')">🏛️ Dept Custody</button>
            <button class="filter-btn" id="dashFilterReturned" onclick="setDashSearchType('returned')">Returned</button>
          </div>
        </div>

        <div id="dashSearchResultsWrap">
          ${renderDashSearchResults()}
        </div>
      `;
    } else if (tabKey === "claims") {
      const myClaims = claims.filter(c => c.claimantUid === user.uid);
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">My Claim Requests</h2>
            <p>Status of ownership claims you submitted. Faculty &amp; Staff verify all proofs.</p>
          </div>
        </div>
        <div class="dash-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Item</th>
                <th>Submitted</th>
                <th>Proof</th>
                <th>Status</th>
                <th>Next Step</th>
              </tr>
            </thead>
            <tbody>
              ${myClaims.length === 0 ? `<tr><td colspan="5" style="text-align:center; padding: 24px;">No claim requests on file.</td></tr>` :
                myClaims.map(c => {
                  const cs = String(c.status || "pending").toLowerCase();
                  const id = safeDocId(c.id);
                  let actions = `<span style="font-size: 12px; color: var(--muted);">⏳ Awaiting staff review</span>`;
                  if (cs === "approved") {
                    actions = `
                      <div class="claim-action-row">
                        <button type="button" class="tbl-action-btn success" data-action="open-chat" data-claim-id="${escapeHtml(id)}">💬 Open chat</button>
                        <button type="button" class="tbl-action-btn" data-action="show-handover" data-claim-id="${escapeHtml(id)}">📱 Handover code</button>
                      </div>`;
                  } else if (cs === "returned") {
                    actions = `<button type="button" class="tbl-action-btn success" data-action="view-receipt" data-claim-id="${escapeHtml(id)}">🧾 View receipt</button>`;
                  } else if (cs === "rejected") {
                    actions = `<span style="font-size: 12px; color: var(--muted);">Contact campus staff if this is a mistake.</span>`;
                  }
                  return `
                  <tr>
                    <td><strong>${escapeHtml(c.itemTitle)}</strong></td>
                    <td data-label="Submitted">${escapeHtml(formatDateTime(c.createdAt))}</td>
                    <td data-label="Proof"><span style="font-size:12px; color:var(--muted);">🔒 Submitted privately</span></td>
                    <td data-label="Status"><span class="tag ${claimStatusClass(cs)}">${escapeHtml(claimStatusLabel(cs))}</span></td>
                    <td data-label="Next Step">${actions}</td>
                  </tr>
                `;
                }).join("")}
            </tbody>
          </table>
        </div>
      `;
    } else if (tabKey === "messages") {
      main.innerHTML = renderMessagesTab();
    } else if (tabKey === "notif-settings") {
      renderNotificationSettingsTab(main);
    } else if (tabKey === "scan-handover" && isStaffSession(user)) {
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Scan Item Handover</h2>
            <p>Scan the claimant's single-use QR code, or type the code shown on their phone.</p>
          </div>
        </div>
        <div class="scanner-panel">
          <div class="scanner-video-wrap">
            <video id="handoverVideo" class="scanner-video" playsinline muted></video>
            <div class="scanner-placeholder" id="scannerPlaceholder">📷 Camera preview appears here</div>
          </div>
          <canvas id="handoverCanvas" hidden></canvas>
          <div class="scanner-actions">
            <button type="button" class="btn-action-primary" id="startScanBtn">Start camera</button>
            <button type="button" class="btn-action-secondary" id="stopScanBtn" disabled>Stop camera</button>
          </div>
          <p class="scanner-status" id="scannerStatus" role="status" aria-live="polite"></p>
          <form id="manualHandoverForm" class="manual-handover-form">
            <label for="manualHandoverToken">Or enter the handover code manually</label>
            <input id="manualHandoverToken" autocomplete="off" spellcheck="false" placeholder="CC1.claimId.code" maxlength="300">
            <button type="submit" class="submit-btn">Verify handover</button>
          </form>
          <div id="handoverResult" class="handover-result" aria-live="polite"></div>
        </div>
      `;
    } else if (tabKey === "notifs") {
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Notifications</h2>
            <p>Real-time alerts regarding your posts, verification status, and matching items.</p>
          </div>
        </div>
        <div style="background: #FFF; border: 1px solid var(--border); border-radius: 6px;">
          ${notifs.length === 0 ? `<div style="padding: 24px; text-align: center; color: var(--muted);">No notifications yet.</div>` :
            notifs.map(n => `
              <div class="notif-item">
                <span class="notif-icon">🔔</span>
                <div>
                  <div class="notif-text">${escapeHtml(n.text)}</div>
                  <div class="notif-time">${escapeHtml(formatDateTime(n.createdAt))}</div>
                </div>
              </div>
            `).join("")}
        </div>
      `;
    } else if (tabKey === "profile") {
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">My Student Profile</h2>
            <p>Your verified campus credential details and access status.</p>
          </div>
          <button class="btn btn-report-item" onclick="openComplaintModal()">⚠️ File Inquiry / Dispute</button>
        </div>
        <div class="dash-info-card" style="background: #FFF; border: 1px solid var(--border); border-radius: 6px; padding: 24px; max-width: 520px; box-shadow: 0 2px 4px rgba(0,0,0,0.03);">
          <div style="margin-bottom: 14px;">
            <label style="margin: 0; color: var(--muted); font-size: 11px;">FULL NAME</label>
            <div style="font-size: 16px; font-weight: 600; color: var(--ink);">${escapeHtml(user.name)}</div>
          </div>
          <div style="margin-bottom: 14px;">
            <label style="margin: 0; color: var(--muted); font-size: 11px;">COLLEGE EMAIL</label>
            <div style="font-size: 15px; color: var(--ink);">${escapeHtml(user.email)}</div>
          </div>
          <div style="margin-bottom: 14px;">
            <label style="margin: 0; color: var(--muted); font-size: 11px;">ROLE</label>
            <div><span class="role-pill">${user.role.toUpperCase()}</span></div>
          </div>
          <div style="margin-bottom: 14px;">
            <label style="margin: 0; color: var(--muted); font-size: 11px;">COLLEGE EMAIL VERIFICATION</label>
            <div><span class="tag approved">✓ Verified Campus Domain</span></div>
          </div>
          <div>
            <label style="margin: 0; color: var(--muted); font-size: 11px;">PERMISSIONS</label>
            <div style="font-size: 12px; color: var(--text); line-height: 1.5; margin-top: 4px;">
              Can report lost &amp; found items, upload photos, edit/delete own reports, search board, send claim requests, and track statuses.
            </div>
          </div>
        </div>
      `;
    }

    /* ================= B. FACULTY / STAFF DASHBOARD TABS ================= */
    else if (tabKey === "fac-lost") {
      const allLost = items.filter(i => i.type === "lost");
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">All Campus Lost Reports</h2>
            <p>Monitor student lost reports across all campus departments.</p>
          </div>
        </div>
        ${renderItemsTable(allLost, false, true)}
      `;
    } else if (tabKey === "fac-found") {
      const allFound = items.filter(i => i.type === "found");
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">All Campus Found Properties</h2>
            <p>Items found and registered into faculty custody or turned in by students.</p>
          </div>
          <button class="btn btn-report-item" onclick="openReportModal(); setReportType('found');">+ Report Found Property</button>
        </div>
        ${renderItemsTable(allFound, false, true)}
      `;
    } else if (tabKey === "fac-pending") {
      const pending = items.filter(i => normalizeStatus(i.status) === "pending" || !i.isStaffVerified);
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Pending Verification Queue</h2>
            <p>Review and verify new student lost and found submissions before board publishing.</p>
          </div>
        </div>
        ${renderItemsTable(pending, false, true, true)}
      `;
    } else if (tabKey === "fac-claims") {
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Claim Requests Review</h2>
            <p>Examine private ownership proofs provided by students to confirm ownership safely.</p>
          </div>
        </div>
        <div class="dash-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Item</th>
                <th>Claimant</th>
                <th>Submitted Private Proof</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${claims.length === 0 ? `<tr><td colspan="5" style="text-align:center; padding: 24px;">No claims pending review.</td></tr>` :
                claims.map(c => {
                  const cs = String(c.status || "pending").toLowerCase();
                  const idArg = handlerArg(safeDocId(c.id));
                  const chatButton = cs === "approved"
                    ? `<button class="tbl-action-btn" data-action="open-chat" data-claim-id="${escapeHtml(safeDocId(c.id))}">💬 Chat</button>`
                    : "";
                  return `
                  <tr>
                    <td><strong>${escapeHtml(c.itemTitle)}</strong></td>
                    <td data-label="Claimant">${escapeHtml(c.claimantName)}<br><span style="font-size:11px; color:var(--muted);">${escapeHtml(c.claimantEmail)}</span></td>
                    <td data-label="Private Proof"><span style="font-size:12px; color:var(--muted);">🔒 Hidden — open review to read</span></td>
                    <td data-label="Status"><span class="tag ${claimStatusClass(cs)}">${escapeHtml(claimStatusLabel(cs))}</span></td>
                    <td data-label="Action">
                      <div class="claim-action-row">
                        <button class="tbl-action-btn success" onclick="openReviewClaimModal(decodeURIComponent('${idArg}'))">Review Proof</button>
                        ${chatButton}
                      </div>
                    </td>
                  </tr>
                `;
                }).join("")}
            </tbody>
          </table>
        </div>
      `;
    } else if (tabKey === "fac-returned") {
      const returned = items.filter(i => normalizeStatus(i.status) === "returned");
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Returned Items Audit Log</h2>
            <p>History of items successfully handed back to verified student owners.</p>
          </div>
        </div>
        ${renderItemsTable(returned, false, true)}
      `;
    } else if (tabKey === "fac-support") {
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Student Support &amp; Verification Desk</h2>
            <p>Department contacts and assistance protocols for lost property claims.</p>
          </div>
          <button class="btn btn-report-item" onclick="openComplaintModal()">⚠️ File Inquiry / Dispute</button>
        </div>
        <div class="dash-info-card" style="background:#FFF; border:1px solid var(--border); border-radius:6px; padding:24px;">
          <h3 class="display" style="font-size:18px; margin-bottom:8px;">Campus Lost &amp; Found Hand-Over Guidelines</h3>
          <ul style="margin-left: 20px; line-height: 1.8; font-size: 13px; color: var(--text);">
            <li><strong>Photo ID Check:</strong> Verify student campus card or government photo ID before releasing valuable items.</li>
            <li><strong>Device Matching:</strong> For phones and laptops, request claimant to unlock with passcode or describe wallpaper.</li>
            <li><strong>Secure Storage:</strong> Keys, wallets, and cash must be held in departmental lockboxes until claimed.</li>
            <li><strong>Custody Registration:</strong> Use the "Take into Dept Custody" option to log office location and pickup hours.</li>
          </ul>
        </div>
      `;
    }

    /* ================= C. ADMIN DASHBOARD TABS ================= */
    else if (tabKey === "admin-overview") {
      const lostCount = items.filter(i => i.type === "lost").length;
      const foundCount = items.filter(i => i.type === "found").length;
      const pendingCount = items.filter(i => normalizeStatus(i.status) === "pending").length;
      const returnedCount = items.filter(i => normalizeStatus(i.status) === "returned").length;
      const claimsCount = claims.length;
      const usersCount = users.length;

      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Campus Connect Command Center</h2>
            <p>Complete administrative control for reports, user permissions, and website statistics.</p>
          </div>
          <div class="dash-header-actions" style="display:flex; gap:8px;">
            <button class="btn btn-admin-action" style="background:var(--ink); color:#FFF;" onclick="openAdminSendNotifModal()">🔔 Dispatch Alert</button>
            <button class="btn btn-admin-action" style="background:var(--custody); color:#FFF;" onclick="exportAuditReportCSV()">📥 Download CSV Log</button>
          </div>
        </div>

        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-label">Total Lost Reports</div>
            <div class="kpi-value">${lostCount}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Total Found Items</div>
            <div class="kpi-value">${foundCount}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Pending Approvals</div>
            <div class="kpi-value" style="color: var(--st-pending);">${pendingCount}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Claims Submitted</div>
            <div class="kpi-value">${claimsCount}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Returned to Owner</div>
            <div class="kpi-value" style="color: var(--st-returned);">${returnedCount}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Registered Accounts</div>
            <div class="kpi-value">${usersCount}</div>
          </div>
        </div>

        <h3 class="display" style="font-size: 19px; margin-bottom: 12px;">Recent Platform Activity</h3>
        <div style="background: #FFF; border: 1px solid var(--border); border-radius: 6px; padding: 16px;">
          ${logs.slice(0, 6).map(l => `
            <div class="dash-log-row">
              <span>⚡ ${escapeHtml(l.text)}</span>
              <span>${escapeHtml(formatDateTime(l.createdAt))}</span>
            </div>
          `).join("")}
        </div>
      `;
    } else if (tabKey === "admin-students") {
      const students = users.filter(u => u.role === "student");
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Manage Student Accounts</h2>
            <p>Active student accounts, permissions, and credential records.</p>
          </div>
          <button class="btn btn-report-item" onclick="openAdminUserModal(null, 'student')">+ Add Student Account</button>
        </div>
        <div class="dash-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Student Name</th>
                <th>College Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${students.map(s => {
                const idArg = handlerArg(safeDocId(s.id));
                const active = (s.status || "Active") === "Active";
                return `
                <tr>
                  <td><strong>${escapeHtml(s.name || "Student")}</strong></td>
                  <td data-label="College Email">${escapeHtml(s.email)}</td>
                  <td data-label="Role"><span class="role-pill">STUDENT</span></td>
                  <td data-label="Status"><span class="tag ${active ? 'approved' : 'rejected'}">${escapeHtml(s.status || 'Active')}</span></td>
                  <td data-label="Actions">
                    <button class="tbl-action-btn" onclick="toggleUserStatus(decodeURIComponent('${idArg}'))">${active ? 'Suspend' : 'Activate'}</button>
                    <button class="tbl-action-btn" onclick="openAdminUserModal(decodeURIComponent('${idArg}'))">Assign Role</button>
                    <button class="tbl-action-btn danger" onclick="deleteUser(decodeURIComponent('${idArg}'))">Remove</button>
                  </td>
                </tr>
              `;
              }).join("")}
            </tbody>
          </table>
        </div>
      `;
    } else if (tabKey === "admin-faculty") {
      const faculty = users.filter(u => u.role === "faculty");
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Manage Faculty / Staff</h2>
            <p>University staff authorized to verify reports, hold custody, and return property.</p>
          </div>
          <button class="btn btn-report-item" onclick="openAdminUserModal(null, 'faculty')">+ Authorize Staff</button>
        </div>
        <div class="dash-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Staff Name</th>
                <th>Faculty Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${faculty.map(f => {
                const idArg = handlerArg(safeDocId(f.id));
                const active = (f.status || "Active") === "Active";
                return `
                <tr>
                  <td><strong>${escapeHtml(f.name || "Staff Member")}</strong></td>
                  <td data-label="Faculty Email">${escapeHtml(f.email)}</td>
                  <td data-label="Role"><span class="role-pill">FACULTY/STAFF</span></td>
                  <td data-label="Status"><span class="tag ${active ? 'approved' : 'rejected'}">${escapeHtml(f.status || 'Active')}</span></td>
                  <td data-label="Actions">
                    <button class="tbl-action-btn" onclick="toggleUserStatus(decodeURIComponent('${idArg}'))">${active ? 'Suspend' : 'Activate'}</button>
                    <button class="tbl-action-btn" onclick="openAdminUserModal(decodeURIComponent('${idArg}'))">Assign Role</button>
                    <button class="tbl-action-btn danger" onclick="deleteUser(decodeURIComponent('${idArg}'))">Revoke</button>
                  </td>
                </tr>
              `;
              }).join("")}
            </tbody>
          </table>
        </div>
      `;
    } else if (tabKey === "admin-lost") {
      const allLost = items.filter(i => i.type === "lost");
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Manage Lost Items</h2>
            <p>Full administrative override on all student lost item reports.</p>
          </div>
        </div>
        ${renderItemsTable(allLost, false, false, false, true)}
      `;
    } else if (tabKey === "admin-found") {
      const allFound = items.filter(i => i.type === "found");
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Manage Found Items</h2>
            <p>Full administrative override on all found property reports.</p>
          </div>
        </div>
        ${renderItemsTable(allFound, false, false, false, true)}
      `;
    } else if (tabKey === "admin-claims") {
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Manage All Claims</h2>
            <p>Campus-wide claim verification and approval console.</p>
          </div>
        </div>
        <div class="dash-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Item</th>
                <th>Claimant</th>
                <th>Private Proof</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${claims.map(c => {
                const cs = String(c.status || "pending").toLowerCase();
                const idArg = handlerArg(safeDocId(c.id));
                const extra = cs === "approved"
                  ? `<button class="tbl-action-btn" data-action="open-chat" data-claim-id="${escapeHtml(safeDocId(c.id))}">💬 Chat</button>`
                  : (cs === "returned"
                    ? `<button class="tbl-action-btn success" data-action="view-receipt" data-claim-id="${escapeHtml(safeDocId(c.id))}">🧾 Receipt</button>`
                    : "");
                return `
                <tr>
                  <td><strong>${escapeHtml(c.itemTitle)}</strong></td>
                  <td data-label="Claimant">${escapeHtml(c.claimantName)}<br><span style="font-size:11px; color:var(--muted);">${escapeHtml(c.claimantEmail)}</span></td>
                  <td data-label="Private Proof"><span style="font-size:12px; color:var(--muted);">🔒 Hidden — open review to read</span></td>
                  <td data-label="Status"><span class="tag ${claimStatusClass(cs)}">${escapeHtml(claimStatusLabel(cs))}</span></td>
                  <td data-label="Actions">
                    <div class="claim-action-row">
                      <button class="tbl-action-btn" onclick="openReviewClaimModal(decodeURIComponent('${idArg}'))">Review</button>
                      ${cs === "pending" ? `<button class="tbl-action-btn success" onclick="resolveClaim(decodeURIComponent('${idArg}'), 'Approved')">Approve</button>
                      <button class="tbl-action-btn danger" onclick="resolveClaim(decodeURIComponent('${idArg}'), 'Rejected')">Reject</button>` : ""}
                      ${extra}
                    </div>
                  </td>
                </tr>
              `;
              }).join("")}
            </tbody>
          </table>
        </div>
      `;
    } else if (tabKey === "admin-categories") {
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Manage Categories</h2>
            <p>Item classification categories available across the website.</p>
          </div>
          <button class="btn btn-report-item" onclick="openCategoryModal()">+ Add Category</button>
        </div>
        <div style="background: #FFF; border: 1px solid var(--border); border-radius: 6px; padding: 20px;">
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            ${cats.map(c => {
              const count = items.filter(i => i.category === c).length;
              return `
                <div style="background: #F7F3EA; border: 1px solid var(--border); padding: 8px 14px; border-radius: 20px; font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                  <span>🏷️ ${escapeHtml(c)} <small style="color:var(--muted);">(${count})</small></span>
                  <button type="button" style="background:none; border:none; cursor:pointer; color:var(--lost);" data-category="${escapeHtml(c)}" onclick="deleteCategory(this.dataset.category)">✕</button>
                </div>
              `;
            }).join("")}
          </div>
        </div>
      `;
    } else if (tabKey === "admin-complaints") {
      const complaints = getComplaints();
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Manage Complaints &amp; Disputes</h2>
            <p>Review disputed claims, department inquiries, and urgent reports.</p>
          </div>
          <button class="btn btn-report-item" onclick="openComplaintModal()">+ Submit Dispute Ticket</button>
        </div>
        <div class="dash-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Ticket &amp; Student</th>
                <th>Subject &amp; Type</th>
                <th>Details</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${complaints.length === 0 ? `<tr><td colspan="5" style="text-align:center; padding: 24px;">No student complaints or disputes logged.</td></tr>` :
                complaints.map(c => {
                  const idArg = handlerArg(safeDocId(c.id));
                  const status = String(c.status || "Under Review");
                  return `
                  <tr>
                    <td>
                      <strong>#${escapeHtml(String(c.id).slice(-6))}</strong><br>
                      ${escapeHtml(c.studentName)}<br>
                      <span style="font-size:11px; color:var(--muted);">${escapeHtml(c.studentEmail)}</span>
                    </td>
                    <td data-label="Subject &amp; Type">
                      <strong>${escapeHtml(c.subject)}</strong><br>
                      <span class="tag" style="background:#2E5B70; font-size:10px;">${escapeHtml(c.type)}</span>
                      <span style="font-size:11px; color:var(--muted);">${escapeHtml(formatDateTime(c.createdAt))}</span>
                    </td>
                    <td data-label="Details" style="max-width:280px; font-size:12px; line-height:1.4;">
                      "${escapeHtml(c.message)}"
                    </td>
                    <td data-label="Status">
                      <span class="tag ${complaintStatusClass(status)}">
                        ${escapeHtml(status)}
                      </span>
                    </td>
                    <td data-label="Actions">
                      ${status !== 'Resolved' ? `
                        <button class="tbl-action-btn success" onclick="updateComplaintStatus(decodeURIComponent('${idArg}'), 'Resolved')">Resolve</button>
                        <button class="tbl-action-btn" onclick="updateComplaintStatus(decodeURIComponent('${idArg}'), 'Investigating')">Investigate</button>
                      ` : `
                        <button class="tbl-action-btn" onclick="updateComplaintStatus(decodeURIComponent('${idArg}'), 'Under Review')">Reopen</button>
                      `}
                    </td>
                  </tr>
                `;
                }).join("")}
            </tbody>
          </table>
        </div>
      `;
    } else if (tabKey === "admin-analytics") {
      const lostCount = items.filter(i => i.type === "lost").length;
      const foundCount = items.filter(i => i.type === "found").length;
      const returnedCount = items.filter(i => normalizeStatus(i.status) === "returned").length;
      const pendingClaimsCount = claims.filter(c => String(c.status || "").toLowerCase() === "pending").length;

      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Reports &amp; Analytics</h2>
            <p>Official lost &amp; found statistics, category distribution, and audit log export.</p>
          </div>
          <button class="btn btn-admin-action" style="background:var(--ink); color:#FFF;" onclick="exportAuditReportCSV()">📥 Download Audit Spreadsheet (.CSV)</button>
        </div>

        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-label">Total Lost Items</div>
            <div class="kpi-value">${lostCount}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Total Found Items</div>
            <div class="kpi-value">${foundCount}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Returned to Owner</div>
            <div class="kpi-value" style="color: var(--st-returned);">${returnedCount}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Pending Claims</div>
            <div class="kpi-value" style="color: var(--st-pending);">${pendingClaimsCount}</div>
          </div>
        </div>

        <div class="analytics-cards-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px;">
          <div style="background:#FFF; border:1px solid var(--border); border-radius:6px; padding: 20px;">
            <h3 class="display" style="font-size:16px; margin-bottom: 12px;">📊 Items by Category</h3>
            <table style="width:100%;">
              <thead>
                <tr><th>Category</th><th>Count</th></tr>
              </thead>
              <tbody>
                ${cats.map(c => `
                  <tr>
                    <td>🏷️ ${escapeHtml(c)}</td>
                    <td><strong>${items.filter(i => i.category === c).length}</strong></td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>

          <div style="background:#FFF; border:1px solid var(--border); border-radius:6px; padding: 20px;">
            <h3 class="display" style="font-size:16px; margin-bottom: 12px;">📍 Top Campus Locations</h3>
            <table style="width:100%;">
              <thead>
                <tr><th>Location</th><th>Items</th></tr>
              </thead>
              <tbody>
                <tr><td>Library Study Pods</td><td><strong>${items.filter(i => (i.location || "").toLowerCase().includes("library")).length}</strong></td></tr>
                <tr><td>Cafeteria &amp; Dining Hall</td><td><strong>${items.filter(i => (i.location || "").toLowerCase().includes("cafeteria")).length}</strong></td></tr>
                <tr><td>Science &amp; Chemistry Labs</td><td><strong>${items.filter(i => (i.location || "").toLowerCase().includes("chemistry") || (i.location || "").toLowerCase().includes("science")).length}</strong></td></tr>
                <tr><td>Gymnasium / Sports Complex</td><td><strong>${items.filter(i => (i.location || "").toLowerCase().includes("gym")).length}</strong></td></tr>
                <tr><td>Bus Stop / Campus Gates</td><td><strong>${items.filter(i => (i.location || "").toLowerCase().includes("gate") || (i.location || "").toLowerCase().includes("bus")).length}</strong></td></tr>
              </tbody>
            </table>
          </div>
        </div>
      `;
    } else if (tabKey === "admin-settings") {
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Website Settings</h2>
            <p>Configure university domains, global announcements, and security policies.</p>
          </div>
        </div>
        <div class="dash-info-card" style="background:#FFF; border:1px solid var(--border); border-radius:6px; padding:24px; max-width: 620px;">
          <div style="margin-bottom: 18px;">
            <label style="font-weight: 700; font-size: 12px;">COLLEGE EMAIL DOMAIN POLICY</label>
            <input value="@campus.edu" disabled style="background:#F7F3EA; font-weight: 600;">
            <p style="font-size: 11px; color: var(--muted); margin-top: 4px;">Enforced for campus authentication. Only users with authorized institutional college email addresses can access the board.</p>
          </div>
          <div style="margin-bottom: 18px;">
            <label style="font-weight: 700; font-size: 12px;">CAMPUS BROADCAST BULLETIN</label>
            <p style="font-size: 12px; color: var(--muted); margin-bottom: 8px;">Displays an urgent announcement banner across the top of all pages.</p>
            <button class="tbl-action-btn" onclick="openBroadcastModal()">📢 Edit Live Notice Banner</button>
          </div>
          <div style="margin-bottom: 18px;">
            <label style="font-weight: 700; font-size: 12px;">SYSTEM NOTIFICATIONS DISPATCH</label>
            <p style="font-size: 12px; color: var(--muted); margin-bottom: 8px;">Send instant alerts to students or faculty members.</p>
            <button class="tbl-action-btn" onclick="openAdminSendNotifModal()">🔔 Dispatch System Notification</button>
          </div>
          <div style="margin-bottom: 18px;">
            <label style="font-weight: 700; font-size: 12px;">SESSION SECURITY</label>
            <p style="font-size: 12px; color: var(--muted); margin-bottom: 8px;">Revoke all refresh tokens for your account on every device.</p>
            <button class="tbl-action-btn" onclick="signOutAllDevicesAction()">🔐 Sign Out of All Devices</button>
          </div>
          <div>
            <label style="font-weight: 700; font-size: 12px;">BATCH DATA CLEANUP</label>
            <p style="font-size: 12px; color: var(--muted); margin-bottom: 8px;">Archive resolved items to maintain optimal bulletin board performance.</p>
            <button class="tbl-action-btn danger" onclick="purgeResolvedItems()">🧹 Clean / Archive All Returned Items</button>
          </div>
        </div>
      `;
    } else if (tabKey === "admin-logs") {
      main.innerHTML = `
        <div class="dash-header">
          <div>
            <h2 class="display">Activity Logs (Audit Trail)</h2>
            <p>Real-time record of all actions, submissions, and verifications across the platform.</p>
          </div>
        </div>
        <div style="background:#FFF; border:1px solid var(--border); border-radius:6px; padding:16px;">
          ${logs.map(l => `
            <div class="dash-log-row">
              <span>📜 ${escapeHtml(l.text)}</span>
              <span>${escapeHtml(formatDateTime(l.createdAt))}</span>
            </div>
          `).join("")}
        </div>
      `;
    }

    bindDashTabActions(tabKey);
  }

  /* =========================================================================
   * LEVEL 2: PREFERENCES, CHAT, QR HANDOVER, SCANNER & PWA
   * ========================================================================= */

  function isChatParticipant(chat, uid) {
    return Boolean(chat && uid && (chat.claimantUid === uid || chat.reporterUid === uid));
  }

  function chatReadAtFor(chatId) {
    return toJsDate(chatReadCache.get(chatId));
  }

  function isChatUnread(chat, uid) {
    if (!chat || !chat.lastMessageAt) return false;
    if (!chat.lastSenderUid || chat.lastSenderUid === uid) return false;
    const lastAt = toJsDate(chat.lastMessageAt);
    if (!lastAt) return false;
    const readAt = chatReadAtFor(chat.id);
    return !readAt || readAt.getTime() < lastAt.getTime();
  }

  function updateMessagesUnreadBadge() {
    const user = getCurrentUser();
    const badge = document.getElementById("messagesUnreadBadge");
    if (!user || !badge) return;
    const count = getChats().filter(c => isChatParticipant(c, user.uid) && isChatUnread(c, user.uid)).length;
    badge.textContent = count > 9 ? "9+" : String(count);
    badge.hidden = count === 0;
  }

  function renderMessagesTab() {
    const user = getCurrentUser();
    if (!user) return "";
    if (currentChatId) return renderChatThreadHtml();

    const chats = getChats().filter(c => isStaffSession(user) || isChatParticipant(c, user.uid));
    const unread = chats.filter(c => isChatParticipant(c, user.uid) && isChatUnread(c, user.uid)).length;
    return `
      <div class="dash-header">
        <div>
          <h2 class="display">Secure Messages</h2>
          <p>Private chats between the claimant and the item reporter. Campus staff can review for moderation.</p>
        </div>
        ${unread ? `<span class="tag pending">${unread} unread</span>` : ""}
      </div>
      ${chats.length === 0 ? `
        <div class="chat-empty">
          <div class="chat-empty-icon">💬</div>
          <h3 class="display">No conversations yet</h3>
          <p>A secure chat opens automatically when a claim is approved.</p>
        </div>
      ` : `
        <div class="chat-list">
          ${chats.map(chat => {
            const canRead = isChatParticipant(chat, user.uid);
            const unreadHere = canRead && isChatUnread(chat, user.uid);
            const closed = chat.status && chat.status !== "open";
            return `
              <button type="button" class="chat-list-item ${unreadHere ? "unread" : ""}"
                data-action="open-chat-thread" data-chat-id="${escapeHtml(safeChatId(chat.id))}">
                <span class="chat-avatar">💬</span>
                <span class="chat-list-body">
                  <span class="chat-list-top">
                    <span class="chat-list-title">${escapeHtml(chat.itemTitle || "Item conversation")}</span>
                    <span class="chat-list-time">${escapeHtml(timeAgo(chat.lastMessageAt || chat.updatedAt))}</span>
                  </span>
                  <span class="chat-list-preview">${escapeHtml(chat.lastMessage || "No messages yet. Say hello!")}</span>
                  <span class="chat-list-flags">
                    ${closed ? `<span class="tag returned">Closed</span>` : ""}
                    ${!canRead ? `<span class="tag approved">Staff view</span>` : ""}
                    ${unreadHere ? `<span class="chat-unread-dot" aria-label="Unread messages"></span>` : ""}
                  </span>
                </span>
              </button>
            `;
          }).join("")}
        </div>
      `}
    `;
  }

  function renderChatThreadHtml() {
    const user = getCurrentUser();
    const chat = getChats().find(c => c.id === currentChatId);
    const closed = Boolean(chat && chat.status && chat.status !== "open");
    const participant = !chat || isChatParticipant(chat, user.uid);
    const canSend = participant && !closed;
    return `
      <div class="chat-thread">
        <div class="chat-thread-head">
          <button type="button" class="btn-mini" data-action="close-chat-thread">← Back</button>
          <div class="chat-thread-title">
            <strong>${escapeHtml((chat && chat.itemTitle) || "Item conversation")}</strong>
            <span>${closed ? "Closed" : "Open"}</span>
          </div>
          <span class="tag ${closed ? "returned" : "approved"}">${closed ? "Closed" : "Secure"}</span>
        </div>
        <div class="chat-messages" id="chatMessages" aria-live="polite"></div>
        ${!participant ? `<p class="chat-readonly-note">Staff moderation view — only the claimant and item reporter can send messages.</p>` : ""}
        ${closed ? `<p class="chat-readonly-note">This chat is closed because the item was returned or the claim ended.</p>` : ""}
        <form id="chatComposeForm" class="chat-compose">
          <input id="chatMessageInput" type="text" maxlength="1000" autocomplete="off"
            placeholder="${closed ? "This chat is closed" : "Write a message…"}" ${canSend ? "" : "disabled"}>
          <button type="submit" class="submit-btn" ${canSend ? "" : "disabled"}>Send</button>
        </form>
        <p class="chat-help">🔒 Messages are only visible to the two participants and campus staff. Do not share passwords or payment details.</p>
      </div>
    `;
  }

  function bindDashTabActions(tabKey) {
    if (tabKey === "messages") {
      updateMessagesUnreadBadge();
      if (currentChatId) bindChatThread();
    } else if (tabKey === "notif-settings") {
      loadNotificationSettings();
    } else if (tabKey === "scan-handover") {
      bindHandoverScanner();
    }
  }

  /**
   * One delegated listener for dashboard/chat/handover buttons. Keeping this in
   * one place avoids inline handlers and re-binding after every render.
   */
  function handleDelegatedAction(event) {
    const handoverButton = event.target.closest("[data-handover-action]");
    if (handoverButton) {
      const action = handoverButton.dataset.handoverAction;
      if (action === "close") closeHandoverModal();
      if (action === "rotate") openHandoverModal(handoverButton.dataset.claimId);
      return;
    }

    const button = event.target.closest("[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    if (action === "open-chat") {
      openChatForClaim(button.dataset.claimId);
    } else if (action === "show-handover") {
      openHandoverModal(button.dataset.claimId);
    } else if (action === "view-receipt") {
      openReceiptModal(button.dataset.claimId);
    } else if (action === "open-chat-thread") {
      openChatThread(button.dataset.chatId);
    } else if (action === "close-chat-thread") {
      closeChatThread();
      renderDashTab("messages");
    } else if (action === "report-message") {
      reportChatMessageFromUi(button.dataset.messageId);
    }
  }

  function renderChatMessages() {
    const box = document.getElementById("chatMessages");
    if (!box) return;
    const user = getCurrentUser();
    const chat = getChats().find(c => c.id === currentChatId);
    box.innerHTML = "";

    if (!chatMessages.length) {
      const empty = document.createElement("p");
      empty.className = "chat-empty-line";
      empty.textContent = "No messages yet. Only the claimant and item reporter can send messages.";
      box.appendChild(empty);
      return;
    }

    let lastDay = "";
    chatMessages.forEach(message => {
      const date = toJsDate(message.createdAt);
      const day = date ? date.toDateString() : "";
      if (day && day !== lastDay) {
        const separator = document.createElement("div");
        separator.className = "chat-date-sep";
        const today = new Date().toDateString();
        const yesterday = new Date(Date.now() - 86400000).toDateString();
        separator.textContent = day === today ? "Today" : (day === yesterday ? "Yesterday" : formatDate(date));
        box.appendChild(separator);
        lastDay = day;
      }

      const mine = Boolean(user && message.senderUid === user.uid);
      const row = document.createElement("div");
      row.className = "chat-message " + (mine ? "mine" : "theirs");

      const bubble = document.createElement("div");
      bubble.className = "chat-bubble";
      // textContent (never innerHTML) so a message can never inject markup.
      bubble.textContent = message.text || "";
      row.appendChild(bubble);

      const meta = document.createElement("div");
      meta.className = "chat-meta";
      let sender = mine ? "You" : "Campus member";
      if (!mine && chat) {
        if (message.senderUid === chat.claimantUid) sender = "Claimant";
        else if (message.senderUid === chat.reporterUid) sender = "Item reporter";
      }
      meta.textContent = sender + " · " + (formatDateTime(message.createdAt) || "Just now");

      if (!mine && message.id) {
        const report = document.createElement("button");
        report.type = "button";
        report.className = "chat-report-btn";
        report.dataset.action = "report-message";
        report.dataset.messageId = safeDocId(message.id);
        report.textContent = "Report";
        meta.appendChild(report);
      }
      row.appendChild(meta);
      box.appendChild(row);
    });
    box.scrollTop = box.scrollHeight;
  }

  function bindChatThread() {
    const form = document.getElementById("chatComposeForm");
    if (form) {
      form.addEventListener("submit", handleChatSend);
    }

    const chat = getChats().find(c => c.id === currentChatId);
    const user = getCurrentUser();
    const participant = !chat || isChatParticipant(chat, user.uid);
    if (chatThreadSubId === currentChatId) {
      renderChatMessages();
      return;
    }
    if (chatThreadUnsub) chatThreadUnsub();
    chatThreadUnsub = null;
    chatThreadSubId = currentChatId;
    const subscribingId = currentChatId;

    chatThreadUnsub = subscribeChatMessages(
      subscribingId,
      (messages) => {
        if (currentChatId !== subscribingId) return;
        chatMessages = messages;
        renderChatMessages();
        if (participant) {
          markChatRead(subscribingId).then(() => {
            chatReadCache.set(subscribingId, new Date());
            updateMessagesUnreadBadge();
          }).catch(() => {});
        }
      },
      () => showToast("Could not load messages. Check your connection.")
    );
  }

  function closeChatThread() {
    if (chatThreadUnsub) {
      chatThreadUnsub();
      chatThreadUnsub = null;
    }
    chatThreadSubId = "";
    currentChatId = "";
    chatMessages = [];
  }

  async function handleChatSend(event) {
    event.preventDefault();
    if (!currentChatId) return;
    const input = document.getElementById("chatMessageInput");
    const form = document.getElementById("chatComposeForm");
    if (!input || !form) return;
    const text = input.value.trim();
    if (!text) return;

    const button = form.querySelector("button[type='submit']");
    if (button) button.disabled = true;
    try {
      await sendChatMessage(currentChatId, text);
      input.value = "";
    } catch (error) {
      showToast(friendlyChatError(error));
    } finally {
      if (button) button.disabled = false;
      input.focus();
    }
  }

  function friendlyChatError(error) {
    const code = String((error && error.code) || "");
    if (code.indexOf("resource-exhausted") !== -1) return "You are sending messages too quickly. Wait a moment.";
    if (code.indexOf("failed-precondition") !== -1) return "This chat is closed.";
    if (code.indexOf("permission-denied") !== -1) return "Only the claimant and item reporter can send messages.";
    return "Message could not be sent. Please try again.";
  }

  async function openChatForClaim(claimId) {
    const id = safeDocId(claimId);
    if (!id) return;
    try {
      const result = await ensureChat(id);
      const chatId = safeChatId(result && result.chatId);
      if (!chatId) throw new Error("No chat returned.");
      openChatThread(chatId);
    } catch (error) {
      showToast("Could not open the secure chat. It is available after a claim is approved.");
    }
  }

  function openChatThread(chatId) {
    const id = safeChatId(chatId);
    if (!id) return;
    currentChatId = id;
    activeDashTab = "messages";
    closeNotificationsModal();
    if (currentMainView !== "dashboard") {
      switchMainView("dashboard");
    } else {
      document.querySelectorAll(".dash-nav-item button").forEach(b => b.classList.remove("active"));
      const button = document.getElementById("btnTab_messages");
      if (button) button.classList.add("active");
      renderDashTab("messages");
    }

    // Deep links may point at a chat that is not in the realtime cache yet.
    if (!getChats().some(chat => chat.id === id) && typeof getChat === "function") {
      getChat(id).then(chat => {
        if (!chat) return;
        cachedChats = cachedChats.filter(c => c.id !== chat.id).concat(chat);
        if (currentChatId === id) renderDashTab("messages");
      }).catch(() => {});
    }
  }

  async function reportChatMessageFromUi(messageId) {
    const safeMessageId = safeDocId(messageId);
    if (!currentChatId || !safeMessageId) return;
    const reason = window.prompt("Why are you reporting this message? Campus staff will review it.");
    if (!reason || !reason.trim()) return;
    try {
      await reportChatMessage(currentChatId, safeMessageId, reason.trim().slice(0, 300));
      showToast("Report sent to campus staff for review. 🛡️");
    } catch (error) {
      showToast("Could not send the report. Please try again.");
    }
  }

  /* -------------------- notification preferences UI -------------------- */

  function renderNotificationSettingsTab(main) {
    main.innerHTML = `
      <div class="dash-header">
        <div>
          <h2 class="display">Notification Settings</h2>
          <p>Choose how Campus Connect contacts you. Security and account notices still appear in the app.</p>
        </div>
      </div>
      <div class="settings-card" id="notifSettingsCard">
        <p class="settings-loading">Loading your preferences…</p>
      </div>
    `;
  }

  function prefToggle(key, label, description) {
    return `
      <label class="pref-row">
        <span class="pref-copy">
          <strong>${escapeHtml(label)}</strong>
          <span>${escapeHtml(description)}</span>
        </span>
        <span class="pref-switch">
          <input type="checkbox" data-pref="${escapeHtml(key)}">
          <span class="pref-slider" aria-hidden="true"></span>
        </span>
      </label>
    `;
  }

  async function loadNotificationSettings() {
    const card = document.getElementById("notifSettingsCard");
    if (!card) return;
    try {
      notificationPrefs = await getUserPreferences();
    } catch (error) {
      notificationPrefs = { pushEnabled: true, emailEnabled: true, claimStatus: true, matchFound: true, chatMessage: true, custodyUpdate: true, broadcast: true, weeklyDigest: false };
    }
    const push = typeof getPushState === "function"
      ? getPushState()
      : { supported: false, configured: false, permission: "unsupported", subscribed: false };
    const pushNote = !push.supported
      ? "This browser does not support push notifications."
      : (!push.configured
        ? "Push is not configured yet. An administrator must add the Firebase VAPID key."
        : (push.permission === "denied"
          ? "Notifications are blocked in browser settings."
          : "Permission is requested only when you press Enable."));
    const installReady = Boolean(deferredInstallPrompt) || /iphone|ipad|ipod/i.test(navigator.userAgent || "");

    card.innerHTML = `
      <section class="settings-section">
        <h3 class="display">Push notifications</h3>
        <p class="settings-help">${escapeHtml(pushNote)}</p>
        <div class="settings-button-row">
          <button type="button" class="btn-action-primary" id="enablePushBtn"
            ${push.supported && push.configured && push.permission !== "denied" ? "" : "disabled"}>Enable push</button>
          <button type="button" class="btn-action-secondary" id="disablePushBtn"
            ${push.subscribed ? "" : "disabled"}>Disable push on this device</button>
        </div>
      </section>

      <section class="settings-section">
        <h3 class="display">What you receive</h3>
        ${prefToggle("pushEnabled", "Push notifications", "Master switch for browser push notifications.")}
        ${prefToggle("emailEnabled", "Email notifications", "Master switch for notification and digest email.")}
        ${prefToggle("claimStatus", "Claim updates", "Claim received, approved, rejected, returned, and receipts.")}
        ${prefToggle("chatMessage", "Chat messages", "A debounced alert when the other participant writes.")}
        ${prefToggle("custodyUpdate", "Pickup and custody updates", "When an item becomes ready for pickup.")}
        ${prefToggle("matchFound", "Possible matches", "When a new report resembles one of your reports.")}
        ${prefToggle("broadcast", "Campus notices", "Administrative announcements sent to everyone.")}
        ${prefToggle("weeklyDigest", "Weekly email digest", "One summary email each Monday. Off by default.")}
      </section>

      <section class="settings-section">
        <h3 class="display">Install the app</h3>
        <p class="settings-help">${installReady
          ? "Install Campus Connect on this device for faster access and reliable notifications."
          : "On iPhone or iPad, open Share → Add to Home Screen to install."}</p>
        <div class="settings-button-row">
          <button type="button" class="btn-action-secondary" id="installAppBtn">Install app</button>
          <button type="button" class="btn-action-secondary" id="flushOfflineBtn">Send queued offline reports</button>
        </div>
        <p class="settings-help" id="offlineQueueHelp"></p>
      </section>
    `;

    Object.keys(notificationPrefs).forEach(key => {
      const input = card.querySelector(`input[data-pref="${key}"]`);
      if (input) input.checked = notificationPrefs[key] !== false;
    });

    card.querySelectorAll("input[data-pref]").forEach(input => {
      input.addEventListener("change", async () => {
        const key = input.dataset.pref;
        if (!key) return;
        const value = input.checked;
        notificationPrefs = { ...notificationPrefs, [key]: value };
        try {
          await saveNotificationPreferences(notificationPrefs);
          showToast("Notification settings saved.");
        } catch (error) {
          input.checked = !value;
          notificationPrefs[key] = !value;
          showToast("Could not save notification settings.");
        }
      });
    });

    const enableBtn = document.getElementById("enablePushBtn");
    if (enableBtn) {
      enableBtn.addEventListener("click", async () => {
        enableBtn.disabled = true;
        try {
          await enablePushNotifications();
          showToast("Push notifications enabled on this device. 🔔");
          loadNotificationSettings();
        } catch (error) {
          showToast(error.message || "Could not enable push notifications.");
          enableBtn.disabled = false;
        }
      });
    }

    const disableBtn = document.getElementById("disablePushBtn");
    if (disableBtn) {
      disableBtn.addEventListener("click", async () => {
        disableBtn.disabled = true;
        try {
          await disablePushNotifications();
          showToast("Push notifications disabled on this device.");
          loadNotificationSettings();
        } catch (error) {
          showToast("Could not disable push notifications.");
          disableBtn.disabled = false;
        }
      });
    }

    const installBtn = document.getElementById("installAppBtn");
    if (installBtn) installBtn.addEventListener("click", triggerInstallPrompt);

    const flushBtn = document.getElementById("flushOfflineBtn");
    if (flushBtn) {
      flushBtn.addEventListener("click", async () => {
        flushBtn.disabled = true;
        try {
          const result = await flushOfflineReports();
          showToast(result.flushed ? `Sent ${result.flushed} queued report(s).` : "No queued reports to send.");
        } catch (error) {
          showToast("Could not send queued reports yet.");
        } finally {
          flushBtn.disabled = false;
          updateOfflineBanner();
        }
      });
    }
    updateOfflineBanner();
  }

  /* ---------------------- QR handover (claimant) ----------------------- */

  function handoverOverlay() {
    return document.getElementById("handoverOverlay");
  }

  function closeHandoverModal() {
    const overlay = handoverOverlay();
    if (overlay) overlay.classList.remove("open");
  }

  async function openHandoverModal(claimId) {
    const id = safeDocId(claimId);
    if (!id) return;
    const overlay = handoverOverlay();
    const content = document.getElementById("handoverContent");
    if (!overlay || !content) return;
    content.innerHTML = `<h2 class="display" id="handoverTitle">Preparing your handover code…</h2><p class="settings-help">This may take a moment.</p>`;
    overlay.classList.add("open");

    try {
      const result = await requestHandoverToken(id);
      renderHandoverCode(result);
    } catch (error) {
      content.innerHTML = `
        <h2 class="display" id="handoverTitle">Handover code unavailable</h2>
        <p class="settings-help">Your claim must be approved before a handover code can be issued, and the item must still be awaiting pickup.</p>
        <button type="button" class="submit-btn" data-handover-action="close">Close</button>
      `;
    }
  }

  function renderHandoverCode(result) {
    const content = document.getElementById("handoverContent");
    if (!content || !result || !result.token) return;
    const token = String(result.token);
    const expiry = result.expiresAt ? formatDateTime(new Date(result.expiresAt)) : "in 24 hours";
    content.innerHTML = `
      <h2 class="display" id="handoverTitle">📱 Show this at pickup</h2>
      <p class="settings-help">${escapeHtml(result.itemTitle || "Your item")}</p>
      <div class="qr-box" id="handoverQrBox"></div>
      <div class="qr-token" id="handoverTokenValue"></div>
      <p class="handover-warning">Single-use code · expires ${escapeHtml(expiry)}. Staff scan it once to mark the item returned. Do not share it publicly.</p>
      <div class="settings-button-row">
        <button type="button" class="btn-action-secondary" data-handover-action="rotate" data-claim-id="${escapeHtml(safeDocId(result.claimId))}">Rotate code</button>
        <button type="button" class="btn-action-secondary" data-handover-action="close">Done</button>
      </div>
    `;

    const tokenEl = document.getElementById("handoverTokenValue");
    if (tokenEl) tokenEl.textContent = token;

    const box = document.getElementById("handoverQrBox");
    if (box && typeof qrcode === "function") {
      try {
        const qr = qrcode(0, "M");
        qr.addData(token);
        qr.make();
        const image = document.createElement("img");
        image.alt = "Single-use handover QR code";
        image.src = qr.createDataURL(6, 8);
        box.appendChild(image);
      } catch (error) {
        box.textContent = "QR rendering is unavailable. Enter the code manually or use another device.";
      }
    }
  }

  async function openReceiptModal(claimId) {
    const id = safeDocId(claimId);
    if (!id) return;
    const overlay = handoverOverlay();
    const content = document.getElementById("handoverContent");
    if (!overlay || !content) return;
    content.innerHTML = `<h2 class="display" id="handoverTitle">Loading receipt…</h2>`;
    overlay.classList.add("open");

    let receipt = null;
    try {
      receipt = await getReturnReceipt(id);
    } catch (error) {
      receipt = null;
    }
    if (!receipt) {
      content.innerHTML = `
        <h2 class="display" id="handoverTitle">Receipt not available</h2>
        <p class="settings-help">A receipt is written only after campus staff scan and verify the handover code.</p>
        <button type="button" class="submit-btn" data-handover-action="close">Close</button>
      `;
      return;
    }

    content.innerHTML = `
      <h2 class="display" id="handoverTitle">🧾 Digital return receipt</h2>
      <div class="handover-receipt">
        <div class="receipt-row"><span>Item</span><strong id="receiptItem"></strong></div>
        <div class="receipt-row"><span>Receipt code</span><strong id="receiptCode"></strong></div>
        <div class="receipt-row"><span>Returned</span><strong id="receiptDate"></strong></div>
        <div class="receipt-row"><span>Verified by</span><strong>Campus staff</strong></div>
      </div>
      <p class="settings-help">Keep this receipt for your records. It is also stored on the claim and can be reopened from this page.</p>
      <button type="button" class="submit-btn" data-handover-action="close">Done</button>
    `;
    const itemEl = document.getElementById("receiptItem");
    const codeEl = document.getElementById("receiptCode");
    const dateEl = document.getElementById("receiptDate");
    if (itemEl) itemEl.textContent = receipt.itemTitle || "Item";
    if (codeEl) codeEl.textContent = receipt.receiptCode || "—";
    if (dateEl) dateEl.textContent = formatDateTime(receipt.returnedAt || receipt.createdAt) || "—";
  }

  /* ---------------------- QR scanner (staff) --------------------------- */

  function bindHandoverScanner() {
    const start = document.getElementById("startScanBtn");
    const stop = document.getElementById("stopScanBtn");
    const form = document.getElementById("manualHandoverForm");
    if (start) start.addEventListener("click", startHandoverScanner);
    if (stop) stop.addEventListener("click", stopHandoverScanner);
    if (form) form.addEventListener("submit", handleManualHandoverSubmit);
  }

  async function startHandoverScanner() {
    if (handoverScanner.running) return;
    const video = document.getElementById("handoverVideo");
    const placeholder = document.getElementById("scannerPlaceholder");
    const status = document.getElementById("scannerStatus");
    const startBtn = document.getElementById("startScanBtn");
    const stopBtn = document.getElementById("stopScanBtn");
    if (!video || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      if (status) status.textContent = "Camera scanning is not supported in this browser. Enter the code manually instead.";
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: "environment" } },
        audio: false
      });
      handoverScanner.stream = stream;
      handoverScanner.running = true;
      video.srcObject = stream;
      video.setAttribute("playsinline", "true");
      video.muted = true;
      await video.play().catch(() => {});
      if (placeholder) placeholder.hidden = true;
      if (startBtn) startBtn.disabled = true;
      if (stopBtn) stopBtn.disabled = false;
      if (status) status.textContent = "Point the camera at the claimant's QR code.";

      handoverScanner.detector = "BarcodeDetector" in window
        ? new window.BarcodeDetector({ formats: ["qr_code"] })
        : null;
      scanHandoverFrame();
    } catch (error) {
      handoverScanner.running = false;
      stopHandoverScanner();
      if (status) {
        status.textContent = "Camera permission was not granted. Enter the handover code manually instead.";
      }
    }
  }

  function stopHandoverScanner() {
    handoverScanner.running = false;
    if (handoverScanner.raf) {
      cancelAnimationFrame(handoverScanner.raf);
      handoverScanner.raf = null;
    }
    if (handoverScanner.stream) {
      handoverScanner.stream.getTracks().forEach(track => track.stop());
      handoverScanner.stream = null;
    }
    const video = document.getElementById("handoverVideo");
    if (video) video.srcObject = null;
    const placeholder = document.getElementById("scannerPlaceholder");
    if (placeholder) placeholder.hidden = false;
    const startBtn = document.getElementById("startScanBtn");
    const stopBtn = document.getElementById("stopScanBtn");
    if (startBtn) startBtn.disabled = false;
    if (stopBtn) stopBtn.disabled = true;
  }

  async function scanHandoverFrame() {
    if (!handoverScanner.running) return;
    const video = document.getElementById("handoverVideo");
    const status = document.getElementById("scannerStatus");
    if (!video || video.readyState < 2) {
      handoverScanner.raf = requestAnimationFrame(scanHandoverFrame);
      return;
    }

    try {
      let value = "";
      if (handoverScanner.detector) {
        const codes = await handoverScanner.detector.detect(video).catch(() => []);
        if (codes && codes.length && codes[0].rawValue) value = codes[0].rawValue;
      } else if (typeof jsQR === "function") {
        const canvas = document.getElementById("handoverCanvas");
        if (canvas) {
          const width = video.videoWidth || 640;
          const height = video.videoHeight || 480;
          const scale = Math.min(1, 720 / Math.max(width, height));
          canvas.width = Math.max(1, Math.round(width * scale));
          canvas.height = Math.max(1, Math.round(height * scale));
          const context = canvas.getContext("2d", { willReadFrequently: true });
          context.drawImage(video, 0, 0, canvas.width, canvas.height);
          const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
          const result = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: "dontInvert"
          });
          if (result && result.data) value = result.data;
        }
      }

      if (value && value.indexOf("CC1.") === 0) {
        stopHandoverScanner();
        const input = document.getElementById("manualHandoverToken");
        if (input) input.value = value.slice(0, 300);
        await verifyHandoverFromUi(value);
        return;
      }
    } catch (error) {
      // Keep scanning; a single unreadable frame is normal.
    }

    if (!handoverScanner.running) return;
    if (status && !handoverScanner.detector && !(typeof jsQR === "function")) {
      status.textContent = "This browser cannot decode QR codes. Enter the handover code manually.";
      return;
    }
    handoverScanner.raf = requestAnimationFrame(scanHandoverFrame);
  }

  async function handleManualHandoverSubmit(event) {
    event.preventDefault();
    const input = document.getElementById("manualHandoverToken");
    const token = input ? input.value.trim() : "";
    if (!token) return;
    stopHandoverScanner();
    await verifyHandoverFromUi(token);
  }

  async function verifyHandoverFromUi(token) {
    const value = String(token || "").trim();
    if (!value) return;
    const status = document.getElementById("scannerStatus");
    const resultBox = document.getElementById("handoverResult");
    if (status) status.textContent = "Verifying handover code…";
    if (resultBox) resultBox.innerHTML = "";

    try {
      const result = await verifyHandoverToken(value);
      if (status) status.textContent = "";
      renderScanSuccess(result);
      showToast("Handover verified. Item marked returned. ✅");
      const input = document.getElementById("manualHandoverToken");
      if (input) input.value = "";
    } catch (error) {
      if (status) status.textContent = "";
      renderScanFailure("This handover code is invalid, expired, or already used. Nothing was changed.");
      showToast("Handover verification failed.");
    }
  }

  function renderScanSuccess(result) {
    const box = document.getElementById("handoverResult");
    if (!box) return;
    box.innerHTML = `
      <div class="scan-success">
        <h3 class="display">✅ Handover complete</h3>
        <div class="receipt-row"><span>Item</span><strong id="scanItemTitle"></strong></div>
        <div class="receipt-row"><span>Receipt code</span><strong id="scanReceiptCode"></strong></div>
        <p class="settings-help">The claim and item are now marked returned. A receipt was sent to the claimant.</p>
      </div>
    `;
    const title = document.getElementById("scanItemTitle");
    const code = document.getElementById("scanReceiptCode");
    if (title) title.textContent = result.itemTitle || "Item";
    if (code) code.textContent = result.receiptCode || "—";
  }

  function renderScanFailure(message) {
    const box = document.getElementById("handoverResult");
    if (!box) return;
    const card = document.createElement("div");
    card.className = "scan-failure";
    const title = document.createElement("h3");
    title.className = "display";
    title.textContent = "❌ Not verified";
    const copy = document.createElement("p");
    copy.className = "settings-help";
    copy.textContent = String(message || "Verification failed.");
    card.appendChild(title);
    card.appendChild(copy);
    box.innerHTML = "";
    box.appendChild(card);
  }

  /* ------------------------ PWA & offline ------------------------------ */

  function updateOfflineBanner() {
    const banner = document.getElementById("offlineBanner");
    if (!banner) return;
    banner.hidden = navigator.onLine;
    const count = document.getElementById("offlineQueueCount");
    if (!count) return;
    if (navigator.onLine) {
      count.textContent = "";
      return;
    }
    if (typeof countOfflineReports !== "function") return;
    countOfflineReports().then(total => {
      if (!navigator.onLine) {
        count.textContent = total ? ` (${total} queued)` : "";
      }
    }).catch(() => {});
  }

  async function queueReportForLater(itemPayload) {
    try {
      await queueOfflineReport(itemPayload);
      closeReportModal();
      updateOfflineBanner();
      showToast("Saved on this device. It will be submitted when you are back online. 📴");
      return true;
    } catch (error) {
      showToast("Offline queue is unavailable. Please try again when you have a connection.");
      return false;
    }
  }

  function setupInstallBanner() {
    const banner = document.getElementById("installBanner");
    if (!banner) return;
    const dismissed = Boolean(getUiPrefs().installDismissed);
    const standalone = window.matchMedia("(display-mode: standalone)").matches ||
      window.navigator.standalone === true;
    if (dismissed || standalone) {
      banner.hidden = true;
      return;
    }

    window.addEventListener("beforeinstallprompt", (event) => {
      event.preventDefault();
      deferredInstallPrompt = event;
      banner.hidden = false;
    });

    if (/iphone|ipad|ipod/i.test(navigator.userAgent || "")) {
      const text = document.getElementById("installBannerText");
      if (text) text.textContent = "Install on iPhone/iPad: tap Share, then Add to Home Screen.";
      banner.hidden = false;
    }

    const installBtn = document.getElementById("installBannerBtn");
    if (installBtn) installBtn.addEventListener("click", triggerInstallPrompt);
    const dismissBtn = document.getElementById("dismissInstallBtn");
    if (dismissBtn) {
      dismissBtn.addEventListener("click", () => {
        banner.hidden = true;
        setUiPref("installDismissed", true);
      });
    }
    window.addEventListener("appinstalled", () => {
      deferredInstallPrompt = null;
      banner.hidden = true;
      showToast("Campus Connect installed. 🎉");
    });
  }

  async function triggerInstallPrompt() {
    if (deferredInstallPrompt) {
      deferredInstallPrompt.prompt();
      const choice = await deferredInstallPrompt.userChoice.catch(() => ({ outcome: "dismissed" }));
      deferredInstallPrompt = null;
      if (choice && choice.outcome === "accepted") {
        const banner = document.getElementById("installBanner");
        if (banner) banner.hidden = true;
        showToast("Installing Campus Connect…");
      }
      return;
    }
    if (/iphone|ipad|ipod/i.test(navigator.userAgent || "")) {
      showToast("Tap Share → Add to Home Screen to install on iOS.");
      return;
    }
    showToast("Use your browser menu → Install app / Add to Home screen.");
  }

  function initPwa() {
    if (pwaInitialized) return;
    pwaInitialized = true;
    if (typeof registerCampusServiceWorker === "function") {
      registerCampusServiceWorker();
    }
    updateOfflineBanner();
    window.addEventListener("offline", updateOfflineBanner);
    window.addEventListener("online", async () => {
      updateOfflineBanner();
      if (typeof flushOfflineReports !== "function") return;
      try {
        const result = await flushOfflineReports();
        if (result.flushed) showToast(`Back online — sent ${result.flushed} queued report(s).`);
      } catch (error) {
        // Leave the queue intact.
      }
      updateOfflineBanner();
    });

    // Foreground FCM messages. Background messages are handled by sw.js.
    if (!foregroundMessagingBound &&
      typeof firebase !== "undefined" &&
      typeof firebase.messaging === "function" &&
      typeof pushConfigurationReady === "function" &&
      pushConfigurationReady()) {
      try {
        firebase.messaging().onMessage(payload => {
          const data = (payload && payload.data) || {};
          showToast(data.body || "You have a new Campus Connect update.");
        });
        foregroundMessagingBound = true;
      } catch (error) {
        // Push may be unsupported in this browser.
      }
    }

    setupInstallBanner();
  }

  function handleDeepLink() {
    const params = new URLSearchParams(window.location.search);
    const chatId = safeChatId(params.get("chat"));
    if (chatId) {
      openChatThread(chatId);
      return true;
    }
    return false;
  }

  async function openNotificationTarget(notifId, url) {
    const id = safeDocId(notifId);
    if (id) {
      const notification = cachedNotifs.find(item => item.id === id);
      if (notification && !notification.read) {
        try {
          await markNotificationsRead([id]);
          notification.read = true;
          renderAuthHeader();
        } catch (error) {}
      }
    }

    closeNotificationsModal();
    const target = safeInternalPath(url);
    if (!target) return;

    // For same-page targets, keep the session and use the in-app router.
    try {
      const parsed = new URL(target, window.location.origin);
      if (parsed.pathname === "/index.html" || parsed.pathname === "/") {
        const chatId = safeChatId(parsed.searchParams.get("chat"));
        if (chatId) {
          window.history.replaceState({}, "", target);
          openChatThread(chatId);
          return;
        }
        if (parsed.searchParams.get("view") === "dashboard") {
          window.history.replaceState({}, "", target);
          activeDashTab = "notifs";
          switchMainView("dashboard");
          return;
        }
      }
    } catch (error) {}
    window.location.href = target;
  }

  async function markAllNotificationsRead() {
    const unreadIds = getNotifs().filter(n => !n.read).map(n => n.id).filter(Boolean);
    if (!unreadIds.length) {
      showToast("No unread notifications.");
      return;
    }
    try {
      await markNotificationsRead(unreadIds);
      unreadIds.forEach(id => {
        const notification = cachedNotifs.find(item => item.id === id);
        if (notification) notification.read = true;
      });
      renderAuthHeader();
      openNotificationsModal();
      showToast("All notifications marked read.");
    } catch (error) {
      showToast("Could not mark notifications read.");
    }
  }

  /* =========================================================================
   * SMART SEARCH HELPERS FOR STUDENT DASHBOARD
   * ========================================================================= */
  function filterDashboardSearch() {
    const wrap = document.getElementById("dashSearchResultsWrap");
    if (wrap) wrap.innerHTML = renderDashSearchResults();
  }

  function setDashSearchType(type) {
    dashSearchType = type;
    ["dashFilterAll", "dashFilterLost", "dashFilterFound", "dashFilterCustody", "dashFilterReturned"].forEach(id => {
      const b = document.getElementById(id);
      if (b) b.classList.remove("active");
    });
    const activeBtn = document.getElementById({
      all: "dashFilterAll",
      lost: "dashFilterLost",
      found: "dashFilterFound",
      custody: "dashFilterCustody",
      returned: "dashFilterReturned"
    }[type]);
    if (activeBtn) activeBtn.classList.add("active");
    filterDashboardSearch();
  }

  function renderDashSearchResults() {
    const items = getItems();
    const keyword = (document.getElementById("dashSearchKeyword")?.value || "").trim().toLowerCase();
    const cat = document.getElementById("dashSearchCategory")?.value || "all";
    const loc = (document.getElementById("dashSearchLocation")?.value || "").trim().toLowerCase();

    const filtered = items.filter(it => {
      const st = normalizeStatus(it.status);
      // Exclude pending or rejected from search results
      if (st === "pending" || st === "rejected") return false;

      // Type filter
      if (dashSearchType === "lost" && it.type !== "lost") return false;
      if (dashSearchType === "found" && it.type !== "found") return false;
      if (dashSearchType === "custody" && !it.isCustody) return false;
      if (dashSearchType === "returned" && st !== "returned") return false;

      // Category filter
      if (cat !== "all" && it.category !== cat) return false;

      // Location filter
      if (loc && !String(it.location || "").toLowerCase().includes(loc) && !String(it.custodyLocation || "").toLowerCase().includes(loc)) return false;

      // Keyword filter
      if (keyword) {
        const text = `${it.title} ${it.desc} ${it.location} ${it.category}`.toLowerCase();
        if (!text.includes(keyword)) return false;
      }

      return true;
    });

    if (filtered.length === 0) {
      return `<div style="background:#FFF; border:1px solid var(--border); border-radius:6px; padding: 32px; text-align: center; color: var(--muted);">No matching items found. Try different search terms or categories.</div>`;
    }

    return `
      <div class="dash-table-wrap">
        <table>
          <thead>
            <tr>
              <th>Item</th>
              <th>Category</th>
              <th>Campus Location</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${filtered.map(it => {
              const st = normalizeStatus(it.status);
              const idArg = handlerArg(safeDocId(it.id));
              return `
              <tr>
                <td>
                  <strong>${escapeHtml(it.title)}</strong>
                  <div style="font-size:11px; color:var(--muted);">${escapeHtml(itemDateLabel(it))} &middot; ${escapeHtml(String(it.type || "").toUpperCase())}</div>
                </td>
                <td data-label="Category">${escapeHtml(it.category)}</td>
                <td data-label="Location">📍 ${escapeHtml(it.location)}</td>
                <td data-label="Status">
                  <span class="tag ${escapeHtml(st)}">${escapeHtml(statusLabel(st))}</span>
                  ${it.isCustody ? `<span class="tag custody">In Custody</span>` : ""}
                </td>
                <td data-label="Action">
                  <button class="tbl-action-btn" onclick="openDetail(decodeURIComponent('${idArg}'))">View Details</button>
                  ${st === "approved" ? `
                    <button class="tbl-action-btn success" onclick="openClaimModal(decodeURIComponent('${idArg}'))">Send Claim</button>
                  ` : ""}
                </td>
              </tr>
            `;
            }).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderItemsTable(itemsList, isStudentOwn = false, isFacultyView = false, isPendingQueue = false, isAdminView = false) {
    if (!itemsList || itemsList.length === 0) {
      return `<div style="background:#FFF; border:1px solid var(--border); border-radius:6px; padding: 32px; text-align: center; color: var(--muted);">No reports found in this section.</div>`;
    }

    return `
      <div class="dash-table-wrap">
        <table>
          <thead>
            <tr>
              <th>Item</th>
              <th>Category</th>
              <th>Location</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${itemsList.map(it => {
              const st = normalizeStatus(it.status);
              const idArg = handlerArg(safeDocId(it.id));
              return `
              <tr>
                <td>
                  <strong>${escapeHtml(it.title)}</strong>
                  <div style="font-size: 11px; color: var(--muted);">${escapeHtml(itemDateLabel(it))} &middot; ${escapeHtml(String(it.type || "").toUpperCase())}</div>
                </td>
                <td data-label="Category">${escapeHtml(it.category)}</td>
                <td data-label="Location">📍 ${escapeHtml(it.location)}</td>
                <td data-label="Status">
                  <div>
                    <span class="tag ${escapeHtml(st)}">${escapeHtml(statusLabel(st))}</span>
                    ${it.isCustody ? `<span class="tag custody" style="display:inline-block; margin-top:2px;">In Custody</span>` : ""}
                  </div>
                </td>
                <td data-label="Actions">
                  <button class="tbl-action-btn" onclick="openDetail(decodeURIComponent('${idArg}'))">View Details</button>
                  ${isStudentOwn ? `
                    <button class="tbl-action-btn" onclick="openStudentEditModal(decodeURIComponent('${idArg}'))">✏️ Edit</button>
                    <button class="tbl-action-btn danger" onclick="deleteItemDirect(null, decodeURIComponent('${idArg}'))">🗑️ Delete</button>
                  ` : ""}
                  ${isPendingQueue ? `
                    <button class="tbl-action-btn success" onclick="verifyReportByStaff(decodeURIComponent('${idArg}'))">✅ Approve</button>
                    <button class="tbl-action-btn danger" onclick="rejectReportByStaff(decodeURIComponent('${idArg}'))">❌ Reject</button>
                  ` : ""}
                  ${isAdminView ? `
                    <button class="tbl-action-btn" onclick="openAdminEditModal(decodeURIComponent('${idArg}'))">✏️ Edit</button>
                    <button class="tbl-action-btn danger" onclick="deleteItemDirect(null, decodeURIComponent('${idArg}'))">🗑️ Delete</button>
                  ` : ""}
                </td>
              </tr>
            `;
            }).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  /* =========================================================================
   * STUDENT EDIT OWN REPORT HELPERS
   * ========================================================================= */
  async function openStudentEditModal(rawId) {
    const user = getCurrentUser();
    const id = safeDocId(rawId);
    const it = getItems().find(i => String(i.id) === id);
    if (!it || !user || it.reporterUid !== user.uid) return;

    document.getElementById("sEditId").value = id;
    document.getElementById("sEditTitle").value = it.title || "";
    document.getElementById("sEditLocation").value = it.location || "";
    document.getElementById("sEditDesc").value = it.desc || "";
    document.getElementById("sEditContact").value = "";

    const catSelect = document.getElementById("sEditCategory");
    const cats = getCategories();
    catSelect.innerHTML = cats.map(c =>
      `<option value="${escapeHtml(c)}" ${c === it.category ? 'selected' : ''}>${escapeHtml(c)}</option>`
    ).join("");

    document.getElementById("studentEditOverlay").classList.add("open");
    try {
      const contact = await getReporterContact(id);
      document.getElementById("sEditContact").value = contact || user.email || "";
    } catch (e) {
      document.getElementById("sEditContact").value = user.email || "";
    }
  }

  function closeStudentEditModal(e) {
    if (e && e.target.id !== "studentEditOverlay") return;
    document.getElementById("studentEditOverlay").classList.remove("open");
  }

  async function handleStudentEditSubmit(e) {
    e.preventDefault();
    const user = getCurrentUser();
    const id = safeDocId(document.getElementById("sEditId").value);
    const it = getItems().find(i => String(i.id) === id);
    if (!it || !user || it.reporterUid !== user.uid) return false;

    try {
      await updateItem(id, {
        title: document.getElementById("sEditTitle").value.trim().slice(0, 100),
        category: document.getElementById("sEditCategory").value,
        location: document.getElementById("sEditLocation").value.trim().slice(0, 160),
        desc: document.getElementById("sEditDesc").value.trim().slice(0, 1000)
      });
      const contact = document.getElementById("sEditContact").value.trim().slice(0, 160);
      await updateItemContact(id, contact);

      closeStudentEditModal();
      renderBoard();
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
      showToast("Your report has been updated! ✏️");
      addLog(`Student updated their report ${id} (${it.title})`);
    } catch (err) {
      showToast("Could not update your report.");
    }
    return false;
  }

  /* =========================================================================
   * COMPLAINT & INQUIRY HELPERS
   * ========================================================================= */
  function openComplaintModal() {
    document.getElementById("compSubject").value = "";
    document.getElementById("compMessage").value = "";
    document.getElementById("complaintOverlay").classList.add("open");
  }

  function closeComplaintModal(e) {
    if (e && e.target.id !== "complaintOverlay") return;
    document.getElementById("complaintOverlay").classList.remove("open");
  }

  async function handleComplaintSubmit(e) {
    e.preventDefault();
    const user = getCurrentUser();
    if (!user) return false;
    const subject = document.getElementById("compSubject").value.trim().slice(0, 120);
    const type = document.getElementById("compCategory").value;
    const message = document.getElementById("compMessage").value.trim().slice(0, 1000);

    if (!subject || !message) return false;

    try {
      await createComplaint({ subject, type, message });
      addLog(`${user.name} filed dispute ticket: "${subject}"`);
      createNotification(user.uid, `Your inquiry/dispute regarding "${subject}" has been submitted to campus administration.`);
      closeComplaintModal();
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
      showToast("Inquiry submitted! Campus Security will review your ticket. ⚠️");
    } catch (err) {
      showToast("Could not submit the inquiry. Please try again.");
    }
    return false;
  }

  async function updateComplaintStatus(rawId, newStatus) {
    if (!isStaffSession(getCurrentUser())) return;
    const id = safeDocId(rawId);
    const c = getComplaints().find(x => String(x.id) === id);
    if (!c) return;
    try {
      await updateComplaintStatusInFirestore(id, newStatus);
      if (c.reporterUid) {
        createNotification(c.reporterUid, `Your dispute ticket "${c.subject}" is now marked ${newStatus}.`);
      }
      if (currentMainView === "dashboard") renderDashTab("admin-complaints");
      showToast(`Dispute updated to ${newStatus}.`);
      addLog(`Admin updated dispute ticket ${id} status to ${newStatus}`);
    } catch (err) {
      showToast("Could not update the dispute.");
    }
  }

  /* =========================================================================
   * ADMIN USER ROLE MANAGEMENT HELPERS
   * ========================================================================= */
  const ADMIN_ROLES = ["student", "faculty", "admin"];

  /**
   * Re-authenticate before sensitive account operations (role change, delete,
   * token revocation). A stolen, already-unlocked browser cannot silently
   * escalate or destroy an account without the password/Google prompt.
   */
  async function requireSensitiveReauth() {
    const password = prompt("Confirm your password to continue (leave blank for Google accounts):");
    if (password === null) return false;
    try {
      await reauthenticate(password);
      return true;
    } catch (err) {
      showToast("Re-authentication failed. No changes were made.");
      return false;
    }
  }

  async function toggleUserStatus(rawId) {
    if (!isAdminSession(getCurrentUser())) return;
    const id = safeDocId(rawId);
    const u = getUsers().find(x => String(x.id) === id);
    if (!u) return;
    const next = (u.status || "Active") === "Active" ? "Suspended" : "Active";
    if (!confirm(`${next === "Suspended" ? "Suspend" : "Reactivate"} ${u.email || "this account"}?`)) return;
    if (!await requireSensitiveReauth()) return;
    try {
      await setUserStatus(id, next);
      showToast(`${u.email || "Account"} is now ${next}.`);
      addLog(`Admin set account ${u.email || id} to ${next}`);
    } catch (err) {
      showToast("Could not update the account status.");
    }
  }

  async function deleteUser(rawId) {
    if (!isAdminSession(getCurrentUser())) return;
    const id = safeDocId(rawId);
    const u = getUsers().find(x => String(x.id) === id);
    if (!u) return;
    if (!confirm(`Permanently delete the account for ${u.email || id}? This cannot be undone.`)) return;
    if (!await requireSensitiveReauth()) return;
    try {
      await deleteUserAccount(id);
      showToast("Account deleted.");
      addLog(`Admin deleted account ${u.email || id}`);
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
    } catch (err) {
      showToast("Could not delete the account.");
    }
  }

  function openAdminUserModal(rawUserId = null, defaultRole = 'student') {
    if (!isAdminSession(getCurrentUser())) return;
    const title = document.getElementById("adminUserModalTitle");
    const idInput = document.getElementById("aUserId");
    const nameInput = document.getElementById("aUserName");
    const emailInput = document.getElementById("aUserEmail");
    const roleSelect = document.getElementById("aUserRole");
    const statusSelect = document.getElementById("aUserStatus");

    const userId = rawUserId ? safeDocId(rawUserId) : "";
    if (userId) {
      const u = getUsers().find(x => String(x.id) === userId);
      if (!u) return;
      title.textContent = `👤 Edit Account & Role: ${u.name || u.email}`;
      idInput.value = userId;
      nameInput.value = u.name || "";
      emailInput.value = u.email || "";
      emailInput.disabled = true; // Email is owned by Firebase Auth and never edited here.
      roleSelect.value = ADMIN_ROLES.includes(u.role) ? u.role : "student";
      statusSelect.value = u.status || "Active";
    } else {
      title.textContent = defaultRole === 'faculty' ? "🏛️ Authorize New Faculty / Staff" : "🎓 Invite New Student Account";
      idInput.value = "";
      nameInput.value = "";
      emailInput.value = "";
      emailInput.disabled = false;
      roleSelect.value = ADMIN_ROLES.includes(defaultRole) ? defaultRole : "student";
      statusSelect.value = "Active";
    }

    document.getElementById("adminUserModal").classList.add("open");
  }

  function closeAdminUserModal(e) {
    if (e && e.target.id !== "adminUserModal") return;
    document.getElementById("adminUserModal").classList.remove("open");
  }

  async function handleAdminUserSubmit(e) {
    e.preventDefault();
    if (!isAdminSession(getCurrentUser())) return false;
    const id = safeDocId(document.getElementById("aUserId").value);
    const name = document.getElementById("aUserName").value.trim().slice(0, 80);
    const email = document.getElementById("aUserEmail").value.trim().toLowerCase().slice(0, 160);
    const role = document.getElementById("aUserRole").value;
    const status = document.getElementById("aUserStatus").value;

    if (!ADMIN_ROLES.includes(role)) {
      showToast("Invalid role selected.");
      return false;
    }

    try {
      if (id) {
        const u = getUsers().find(x => String(x.id) === id);
        if (!u) return false;

        // Sensitive actions share a single re-authentication prompt.
        let reauthenticated = false;
        const ensureReauth = async () => {
          if (reauthenticated) return true;
          const ok = await requireSensitiveReauth();
          if (ok) reauthenticated = true;
          return ok;
        };

        // Custom claims are the only authoritative role source, so a role
        // change must go through the admin-only callable.
        if (u.role !== role) {
          if (!await ensureReauth()) return false;
          await setUserRole(id, role);
        }
        // Status is enforced in Auth too, so it also uses a callable.
        if ((u.status || "Active") !== status) {
          if (!await ensureReauth()) return false;
          await setUserStatus(id, status);
        }
        if ((u.name || "") !== name) {
          await adminUpdateUserProfile(id, { name });
        }
        showToast(`Updated account for ${name || email} (${role.toUpperCase()})`);
        addLog(`Admin updated user role/status: ${email} -> ${role}`);
      } else {
        if (!email) {
          showToast("A college email address is required.");
          return false;
        }
        // The inviteUser callable creates the Auth user + profile document and
        // returns a one-time password-reset link. No password ever passes
        // through the UI and no SMTP credentials are stored in the browser.
        const invited = await inviteUser(name, email, role, status);
        if (invited && invited.inviteLink) {
          window.prompt(
            "Account created. Share this one-time invitation link with the user over a trusted channel:",
            invited.inviteLink
          );
        }
        showToast(`Saved ${role.toUpperCase()} account for ${email}.`);
        addLog(`Admin added ${role} account: ${email}`);
      }

      closeAdminUserModal();
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
    } catch (err) {
      console.warn("Admin user update failed:", err.message);
      showToast("Could not save the account. Please try again.");
    }
    return false;
  }

  async function signOutAllDevicesAction() {
    if (!confirm("Sign out of all devices, including this one?")) return;
    try {
      await signOutAllDevices();
      showToast("All sessions revoked. Please sign in again.");
      setTimeout(() => handleLogout(), 800);
    } catch (err) {
      showToast("Could not revoke sessions.");
    }
  }

  /* =========================================================================
   * ADMIN SEND SYSTEM NOTIFICATION
   * ========================================================================= */
  function openAdminSendNotifModal() {
    if (!isAdminSession(getCurrentUser())) return;
    document.getElementById("notifMessageInput").value = "";
    document.getElementById("adminSendNotifModal").classList.add("open");
  }

  function closeAdminSendNotifModal(e) {
    if (e && e.target.id !== "adminSendNotifModal") return;
    document.getElementById("adminSendNotifModal").classList.remove("open");
  }

  async function handleAdminSendNotifSubmit(e) {
    e.preventDefault();
    if (!isAdminSession(getCurrentUser())) return false;
    const audience = document.getElementById("notifRecipient").value;
    const message = document.getElementById("notifMessageInput").value.trim().slice(0, 500);
    if (!message) return false;

    try {
      await dispatchCampusNotification(audience, message);
      addLog(`Admin dispatched system notification to ${audience}`);
      closeAdminSendNotifModal();
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
      showToast("Notification dispatched across campus! 🚀");
    } catch (err) {
      showToast("Could not dispatch the notification.");
    }
    return false;
  }

  function openCategoryModal() {
    if (!isAdminSession(getCurrentUser())) return;
    document.getElementById("newCategoryInput").value = "";
    document.getElementById("categoryOverlay").classList.add("open");
  }
  function closeCategoryModal(e) {
    if (e && e.target.id !== "categoryOverlay") return;
    document.getElementById("categoryOverlay").classList.remove("open");
  }
  async function handleAddCategorySubmit(e) {
    e.preventDefault();
    if (!isAdminSession(getCurrentUser())) return false;
    const name = document.getElementById("newCategoryInput").value.trim().slice(0, 80);
    if (!name) return false;
    const cats = getCategories();
    if (!cats.includes(name)) {
      const next = cats.concat(name);
      try {
        await persistCategories(next);
        populateCategoryDropdowns();
        closeCategoryModal();
        renderDashTab("admin-categories");
        showToast(`Added category: ${name}`);
        addLog(`Added category "${name}"`);
      } catch (err) {
        showToast("Could not add the category.");
      }
    }
    return false;
  }
  async function deleteCategory(catName) {
    if (!isAdminSession(getCurrentUser())) return;
    const name = String(catName || "");
    if (!confirm(`Delete category "${name}"?`)) return;
    let cats = getCategories();
    cats = cats.filter(c => c !== name);
    try {
      await persistCategories(cats);
      populateCategoryDropdowns();
      renderDashTab("admin-categories");
      showToast(`Category removed.`);
    } catch (err) {
      showToast("Could not remove the category.");
    }
  }

  async function purgeResolvedItems() {
    if (!isAdminSession(getCurrentUser())) return;
    const resolved = getItems().filter(i => ["returned", "claimed"].includes(normalizeStatus(i.status)));
    if (resolved.length === 0) {
      alert("No returned or claimed items to clean.");
      return;
    }
    if (!confirm(`Permanently remove ${resolved.length} returned/claimed reports from the board?`)) return;
    try {
      await deleteItems(resolved.map(i => i.id));
      renderBoard();
      renderAdminBanner();
      if (currentMainView === "dashboard") renderDashTab(activeDashTab);
      showToast(`Archived ${resolved.length} resolved items.`);
    } catch (err) {
      showToast("Could not archive resolved items.");
    }
  }

  function exportAuditReportCSV() {
    if (!isAdminSession(getCurrentUser())) return;
    // Contact information is deliberately excluded: it lives in the private
    // subcollection and must not be exported into an unprotected CSV file.
    const items = getItems();
    const headers = ["ID", "Type", "Title", "Category", "Location", "Date", "Status", "InCustody", "CustodyOffice", "Reporter"];
    // SECURITY: quoting alone does not stop spreadsheet formula injection. If a
    // remote title starts with =, +, -, @, tab or CR, prefix an apostrophe so
    // Excel/Sheets treats it as text instead of executing it.
    const csvCell = value => {
      let text = String(value === null || value === undefined ? "" : value).replace(/"/g, '""');
      if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
      return `"${text}"`;
    };
    const rows = items.map(it => [
      csvCell(it.id),
      csvCell(it.type),
      csvCell(it.title),
      csvCell(it.category),
      csvCell(it.location),
      csvCell(itemDateLabel(it)),
      csvCell(statusLabel(it.status)),
      it.isCustody ? "YES" : "NO",
      csvCell(it.custodyLocation),
      csvCell(it.reporterName || it.posterName)
    ]);

    const blob = new Blob([headers.map(csvCell).join(",") + "\n" + rows.map(r => r.join(",")).join("\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `campus_connect_audit_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    showToast("Audit Log CSV downloaded! 📥");
  }

  /* =========================================================================
   * NOTIFICATIONS MODAL
   * ========================================================================= */
  function openNotificationsModal() {
    const notifs = getNotifs();
    const container = document.getElementById("notifListContainer");
    if (!container) return;

    // Opening the list must NOT mark everything read: doing so would hide the
    // unread state for alerts the user never actually looked at. A notification
    // is marked read only when the user opens it (or presses "Mark all read").
    if (notifs.length === 0) {
      container.innerHTML = `<div style="padding: 24px; text-align: center; color: var(--muted);">No notifications at this time.</div>`;
    } else {
      container.innerHTML = notifs.map(n => {
        const id = safeDocId(n.id);
        const url = safeInternalPath(n.url);
        const tag = url ? "button" : "div";
        const attrs = url
          ? ` type="button" class="notif-item notif-item-link ${n.read ? "" : "unread"}" data-action="open-notification" data-notif-id="${escapeHtml(id)}" data-notif-url="${escapeHtml(url)}"`
          : ` class="notif-item ${n.read ? "" : "unread"}"`;
        return `
          <${tag}${attrs}>
            <span class="notif-icon">🔔</span>
            <span class="notif-copy">
              <span class="notif-text">${escapeHtml(n.text)}</span>
              <span class="notif-time">${escapeHtml(formatDateTime(n.createdAt))}</span>
            </span>
            ${url ? `<span class="notif-chevron" aria-hidden="true">›</span>` : ""}
          </${tag}>
        `;
      }).join("");
    }

    const markAll = document.getElementById("markAllNotifsBtn");
    if (markAll) markAll.hidden = !notifs.some(n => !n.read);

    document.getElementById("notifOverlay").classList.add("open");
  }

  function closeNotificationsModal(e) {
    if (e && e.target.id !== "notifOverlay") return;
    document.getElementById("notifOverlay").classList.remove("open");
  }

  /* =========================================================================
   * SESSION IDLE TIMEOUT
   * -------------------------------------------------------------------------
   * A 30-minute inactivity limit reduces the risk of an unattended browser
   * being used to read private proof/contact data or perform staff actions.
   * ========================================================================= */
  const IDLE_WARNING_MS = 25 * 60 * 1000;
  const IDLE_LOGOUT_MS = 30 * 60 * 1000;
  let idleWarningTimer = null;
  let idleLogoutTimer = null;

  function resetIdleTimers() {
    if (!getCurrentUser()) return;
    clearTimeout(idleWarningTimer);
    clearTimeout(idleLogoutTimer);
    idleWarningTimer = setTimeout(() => {
      showToast("You will be signed out in 5 minutes due to inactivity.");
    }, IDLE_WARNING_MS);
    idleLogoutTimer = setTimeout(() => {
      showToast("Signed out due to inactivity.");
      if (typeof firebaseSignOut === "function") firebaseSignOut();
      window.location.href = "login.html";
    }, IDLE_LOGOUT_MS);
  }

  ["click", "keydown", "mousemove", "touchstart"].forEach(evt => {
    window.addEventListener(evt, resetIdleTimers, { passive: true });
  });

  /* =========================================================================
   * INITIALIZATION
   * ========================================================================= */
  function refreshDashboardIfVisible() {
    if (currentMainView !== "dashboard") return;
    // Do not re-render an actively typed-in search form on every snapshot.
    if (activeDashTab === "search-items") return;
    renderDashTab(activeDashTab);
  }

  function startRealtimeSync() {
    if (typeof setupFirebaseSync !== "function") return;
    setupFirebaseSync({
      onItems(list) {
        cachedItems = list;
        renderBoard();
        renderAdminBanner();
        refreshDashboardIfVisible();
      },
      onClaims(list) {
        cachedClaims = list;
        refreshDashboardIfVisible();
      },
      onNotifs(list) {
        cachedNotifs = list;
        renderAuthHeader();
        if (currentMainView === "dashboard" && activeDashTab === "notifs") renderDashTab("notifs");
      },
      onCategories(list) {
        cachedCategories = Array.isArray(list) && list.length ? list.slice() : DEFAULT_CATEGORIES.slice();
        populateCategoryDropdowns();
        renderBoard();
        if (currentMainView === "dashboard" && activeDashTab === "admin-categories") renderDashTab("admin-categories");
      },
      onBroadcast(text) {
        cachedBroadcast = { text: text || "" };
        renderCampusBroadcast();
      },
      onUsers(list) {
        cachedUsers = list;
        if (currentMainView === "dashboard" && ["admin-students", "admin-faculty"].includes(activeDashTab)) {
          renderDashTab(activeDashTab);
        }
      },
      onComplaints(list) {
        cachedComplaints = list;
        if (currentMainView === "dashboard" && activeDashTab === "admin-complaints") renderDashTab(activeDashTab);
      },
      onLogs(list) {
        // Legacy/function entries may not have `text`; derive a readable label
        // without ever inserting it as HTML (the UI escapes it).
        cachedLogs = (list || []).map(entry => ({
          ...entry,
          text: entry.text || entry.details || entry.action || "Activity"
        }));
        if (currentMainView === "dashboard" && ["admin-overview", "admin-logs"].includes(activeDashTab)) {
          renderDashTab(activeDashTab);
        }
      }
    });
  }

  function handleAuthStateChange(session, meta) {
    if (!session) {
      if (meta && meta.notRegistered) {
        showToast(meta.error || "Access Denied: Your email is not registered in the campus directory.");
        setTimeout(() => { window.location.href = "login.html"; }, 1200);
        return;
      }
      if (meta && meta.needsVerification) {
        showToast("Please verify your college email before using the board.");
        setTimeout(() => { window.location.href = "login.html"; }, 1200);
        return;
      }
      if (meta && meta.suspended) {
        showToast("This account is suspended. Contact campus administration.");
        setTimeout(() => { window.location.href = "login.html"; }, 1200);
        return;
      }

      // Guest visitor — show the public bulletin board.
      try { sessionStorage.removeItem("postLoginRedirect"); } catch (e) {}
      populateCategoryDropdowns();
      renderAuthHeader();
      renderBoard();
      startRealtimeSync();
      hideAuthOverlay();
      return;
    }

    populateCategoryDropdowns();
    renderAuthHeader();
    startRealtimeSync();
    resetIdleTimers();

    // Check if the user navigated with ?view=dashboard or just logged in
    let shouldOpenDashboard = false;
    try {
      const params = new URLSearchParams(window.location.search);
      if (params.get("view") === "dashboard" || sessionStorage.getItem("postLoginRedirect") === "dashboard") {
        shouldOpenDashboard = true;
        sessionStorage.removeItem("postLoginRedirect");
      }
    } catch (e) {}

    if (shouldOpenDashboard) {
      switchMainView("dashboard");
    } else {
      renderBoard();
    }
    hideAuthOverlay();
  }

  window.addEventListener("DOMContentLoaded", () => {
    // Safety fallback: if auth takes longer than 5 seconds, reveal the board
    setTimeout(hideAuthOverlay, 5000);

    populateCategoryDropdowns();
    renderAuthHeader();
    renderBoard();

    // Notification modal actions (no inline handlers, delegation only).
    const markAllBtn = document.getElementById("markAllNotifsBtn");
    if (markAllBtn) markAllBtn.addEventListener("click", markAllNotificationsRead);
    const notifList = document.getElementById("notifListContainer");
    if (notifList) {
      notifList.addEventListener("click", (event) => {
        const item = event.target.closest("[data-action='open-notification']");
        if (!item) return;
        openNotificationTarget(item.dataset.notifId, item.dataset.notifUrl);
      });
    }

    document.addEventListener("click", handleDelegatedAction);

    const handoverClose = document.getElementById("handoverCloseBtn");
    if (handoverClose) handoverClose.addEventListener("click", () => closeHandoverModal());
    const handoverOverlayEl = document.getElementById("handoverOverlay");
    if (handoverOverlayEl) {
      handoverOverlayEl.addEventListener("click", (event) => {
        if (event.target === handoverOverlayEl) closeHandoverModal();
      });
    }

    if (typeof initPwa === "function") initPwa();

    // Single auth listener: the service derives role from the ID token claim.
    if (typeof setupAuthListener === "function") {
      setupAuthListener((session, meta) => {
        handleAuthStateChange(session, meta);
        if (session) handleDeepLink();
      });
    } else {
      populateCategoryDropdowns();
      renderAuthHeader();
      renderBoard();
    }
  });

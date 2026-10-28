let db = { courses: [], allocations: [], rooms: [], roomColors: {}, workspace: [], dailyPayments: [], expenses: [], owners: [], closings: [] };
let currentPermissions = new Set();
let authSetupRequired = false;
let selectedAllocationRooms = null;

// ================= ACCESS CONTROL =================
const PERMISSION_LABELS = {
  "data.view": "عرض بيانات النظام",
  "courses.manage": "إدارة المواد والكورسات",
  "courses.view": "عرض المواد والكورسات",
  "courses.edit": "تعديل المواد والكورسات",
  "courses.delete": "حذف المواد والكورسات",
  "allocations.manage": "إدارة توزيع القاعات والجداول",
  "allocations.view": "عرض توزيع القاعات والجداول",
  "allocations.edit": "تعديل توزيع القاعات والجداول",
  "allocations.delete": "حذف تخصيصات وقاعات",
  "students.manage": "إدارة بيانات الطلاب",
  "students.view": "عرض بيانات الطلاب",
  "students.edit": "تعديل بيانات الطلاب",
  "students.delete": "حذف بيانات الطلاب",
  "attendance.manage": "إدارة الحضور",
  "attendance.view": "عرض سجلات الحضور",
  "attendance.edit": "تعديل سجلات الحضور",
  "attendance.delete": "حذف سجلات الحضور",
  "payments.manage": "إدارة المدفوعات",
  "payments.view": "عرض المدفوعات",
  "payments.edit": "تعديل المدفوعات",
  "payments.delete": "حذف المدفوعات",
  "workspace.manage": "إدارة الورك سبيس",
  "workspace.view": "عرض الورك سبيس",
  "workspace.edit": "تعديل الورك سبيس",
  "workspace.delete": "حذف سجلات الورك سبيس",
  "expenses.manage": "إدارة المصروفات",
  "expenses.view": "عرض المصروفات",
  "expenses.edit": "تعديل المصروفات",
  "expenses.delete": "حذف المصروفات",
  "closing.manage": "إدارة الأرباح والإقفالات",
  "closing.view": "عرض الأرباح والإقفالات",
  "closing.edit": "تعديل الأرباح والإقفالات",
  "closing.delete": "حذف الملاك والإقفالات",
  "backups.manage": "إدارة النسخ الاحتياطية",
  "backups.view": "عرض النسخ الاحتياطية",
  "backups.edit": "إرسال النسخ الاحتياطية",
  "backups.delete": "استبدال بيانات النظام من نسخة احتياطية",
  "users.manage": "إدارة المستخدمين والأدوار",
  "users.view": "عرض المستخدمين والأدوار",
  "users.edit": "إضافة وتعديل المستخدمين والأدوار",
  "users.delete": "حذف المستخدمين والأدوار"
};

const ROLE_MODULES = [
  { key: "courses", permission: "courses.manage", label: "المواد والكورسات" },
  { key: "allocations", permission: "allocations.manage", label: "توزيع القاعات والجداول" },
  { key: "students", permission: "students.manage", label: "الطلاب" },
  { key: "attendance", permission: "attendance.manage", label: "الحضور" },
  { key: "payments", permission: "payments.manage", label: "المدفوعات" },
  { key: "workspace", permission: "workspace.manage", label: "الورك سبيس" },
  { key: "expenses", permission: "expenses.manage", label: "المصروفات" },
  { key: "closing", permission: "closing.manage", label: "الأرباح والإقفالات" },
  { key: "backups", permission: "backups.manage", label: "النسخ الاحتياطية" },
  { key: "users", permission: "users.manage", label: "المستخدمون والأدوار" }
];
const TAB_PERMISSIONS = {
  daily: "data.view",
  courses: ["courses.view", "students.view", "attendance.view", "payments.view"],
  allocation: "allocations.view",
  students: "students.view",
  professors: "courses.view",
  workspace: "workspace.view",
  expenses: "expenses.view",
  closing: "closing.view",
  admin: "users.view"
};
const DATA_VIEW_REQUIRED_MODULES = new Set([
  "courses", "students", "attendance", "payments", "workspace", "expenses", "closing"
]);

function requirePermission(permission, callback) {
  if (!hasPermission(permission)) return;
  callback();
}

function requireAllocationPermission(callback) {
  requirePermission('allocations.manage', callback);
}

function requireDeletePermission(permission, callback) {
  requirePermission(permission.replace(/\.manage$/, '.delete'), callback);
}

function hasPermission(permission) {
  if (!currentPermissions.has(permission)) {
    alert(`ليس لديك صلاحية ${PERMISSION_LABELS[permission] || permission}.`);
    return false;
  }
  return true;
}

function openChangePasswordModal() {
  document.getElementById('current-pwd-input').value = '';
  document.getElementById('new-pwd-input').value = '';
  document.getElementById('confirm-pwd-input').value = '';
  document.getElementById('modal-change-password').classList.add('open');
}

function saveNewPassword() {
  const cur = document.getElementById('current-pwd-input').value;
  const n1 = document.getElementById('new-pwd-input').value;
  const n2 = document.getElementById('confirm-pwd-input').value;

  if (!n1 || n1.length < 12) {
    alert('كلمة المرور الجديدة يجب ألا تقل عن 12 حرفًا أو رقمًا');
    return;
  }
  if (n1 !== n2) {
    alert('كلمة المرور الجديدة غير متطابقة!');
    return;
  }

  fetch('/api/auth/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ oldPassword: cur, newPassword: n1 })
  }).then(async response => {
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'تعذر تغيير كلمة المرور');
    closeModal('modal-change-password');
    alert('تم تغيير كلمة المرور بنجاح.');
  }).catch(error => alert(error.message));
}

function openBackupModal() {
  if (!currentPermissions.has('backups.view')) {
    alert('ليس لديك صلاحية إدارة النسخ الاحتياطية.');
    return;
  }
  document.getElementById('modal-backup-info').classList.add('open');
}

async function saveDB() {
  let accessDenied = false;
  try {
    const allocationOnly = !currentPermissions.has('data.view') &&
      currentPermissions.has('allocations.manage');
    const url = allocationOnly ? '/api/allocation-data' : '/api/data';
    const payload = allocationOnly
      ? { allocations: db.allocations, rooms: db.rooms, roomColors: db.roomColors }
      : db;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok) {
      accessDenied = response.status === 401 || response.status === 403;
      throw new Error(result.error || 'تعذر حفظ البيانات');
    }
  } catch (err) {
    console.error(err);
    alert(err.message || 'تعذر حفظ البيانات في الملف. تأكد أن البرنامج يعمل من start.bat');
    if (accessDenied) location.reload();
  }
}

async function initDB() {
  const sessionResponse = await fetch('/api/auth/session');
  const session = await sessionResponse.json();
  if (!session.authenticated) {
    showAuthForm(session.setupRequired);
    return false;
  }
  document.getElementById('modal-auth').classList.remove('open');
  currentPermissions = new Set(session.permissions || []);
  document.getElementById('current-user-label').textContent = `${session.username} (${session.role})`;
  applyPermissionsToUI();
  if (!currentPermissions.has('data.view')) {
    if (currentPermissions.has('allocations.view')) {
      const allocationResponse = await fetch('/api/allocation-data');
      if (!allocationResponse.ok) throw new Error('تعذر تحميل بيانات توزيع القاعات والجداول.');
      db = await allocationResponse.json();
      if (!Array.isArray(db.courses)) db.courses = [];
      if (!Array.isArray(db.allocations)) db.allocations = [];
      if (!Array.isArray(db.rooms)) db.rooms = [];
      if (!db.roomColors || typeof db.roomColors !== 'object' || Array.isArray(db.roomColors)) db.roomColors = {};
      if (ensureAllocationRoomColors() && currentPermissions.has('allocations.edit')) await saveDB();
      switchTab('allocation');
    } else if (currentPermissions.has('users.view')) switchTab('admin');
    else switchTab('access-denied');
    return true;
  }
  const dataRes = await fetch('/api/data');
  if (!dataRes.ok) throw new Error('ليس لديك صلاحية عرض البيانات.');
  db = await dataRes.json();
  if (!db.courses) db.courses = [];
  if (!db.allocations) db.allocations = [];
  if (!db.rooms) db.rooms = [];
  if (!db.roomColors || typeof db.roomColors !== 'object' || Array.isArray(db.roomColors)) db.roomColors = {};
  if (!db.workspace) db.workspace = [];
  if (!db.dailyPayments) db.dailyPayments = [];
  if (!db.expenses) db.expenses = [];
  if (!db.owners) db.owners = [];
  if (!db.closings) db.closings = [];

  const local = localStorage.getItem('asia_center_db_v1');
  if (local) {
    try {
      const localDb = JSON.parse(local);
      const localPay = (localDb.dailyPayments || []).length;
      const filePay = (db.dailyPayments || []).length;
      const localCourses = (localDb.courses || []).length;
      const fileCourses = (db.courses || []).length;
      const localExpenses = (localDb.expenses || []).length;
      const fileExpenses = db.expenses.length;
      const localClosings = (localDb.closings || []).length;
      const fileClosings = db.closings.length;
      if (localPay > filePay || localCourses > fileCourses || localExpenses > fileExpenses || localClosings > fileClosings) {
        if (localExpenses < fileExpenses) localDb.expenses = db.expenses;
        if (localClosings < fileClosings) localDb.closings = db.closings;
        if ((localDb.owners || []).length < db.owners.length) localDb.owners = db.owners;
        if (!localDb.dailyPayments) localDb.dailyPayments = db.dailyPayments;
        if (!localDb.owners) localDb.owners = db.owners;
        localDb.roomColors = { ...(localDb.roomColors || {}), ...(db.roomColors || {}) };
        db = localDb;
        saveDB();
      }
    } catch (e) {
      console.error(e);
    }
  }
  if (!db.allocations) db.allocations = [];
  if (!db.rooms) db.rooms = [];
  if (!db.roomColors || typeof db.roomColors !== 'object' || Array.isArray(db.roomColors)) db.roomColors = {};
  if (ensureAllocationRoomColors() && currentPermissions.has('allocations.manage')) saveDB();

  return true;
}

function showAuthForm(setupRequired) {
  authSetupRequired = setupRequired;
  document.getElementById('auth-title').textContent = setupRequired ? 'إنشاء حساب المدير' : 'تسجيل الدخول';
  document.getElementById('auth-description').textContent = setupRequired
    ? 'أنشئ حساب المدير الأول. كلمة المرور يجب أن تتكون من 12 حرفًا أو رقمًا على الأقل.'
    : 'سجل الدخول للمتابعة إلى نظام سنتر آسيا.';
  document.getElementById('auth-confirm-group').style.display = setupRequired ? 'block' : 'none';
  document.getElementById('auth-password').autocomplete = setupRequired ? 'new-password' : 'current-password';
  document.getElementById('auth-submit').textContent = setupRequired ? 'إنشاء المدير' : 'دخول';
  document.getElementById('modal-auth').classList.add('open');
}

async function submitAuthForm(event) {
  event.preventDefault();
  const password = document.getElementById('auth-password').value;
  if (authSetupRequired && password !== document.getElementById('auth-confirm-password').value) {
    document.getElementById('auth-error').textContent = 'كلمتا المرور غير متطابقتين.';
    return;
  }
  document.getElementById('auth-error').textContent = '';
  try {
    const response = await fetch(authSetupRequired ? '/api/auth/setup' : '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('auth-username').value.trim(),
        password
      })
    });
    const result = await response.json();
    if (!response.ok) {
      document.getElementById('auth-error').textContent = result.error || 'تعذر تسجيل الدخول.';
      return;
    }
  } catch (error) {
    console.error(error);
    document.getElementById('auth-error').textContent = 'تعذر الاتصال بالخادم. تحقق من تشغيل البرنامج.';
    return;
  }
  document.getElementById('auth-password').value = '';
  document.getElementById('auth-confirm-password').value = '';
  document.getElementById('modal-auth').classList.remove('open');
  await startAuthenticatedApp();
}

async function logoutUser() {
  await fetch('/api/auth/logout', { method: 'POST' });
  currentPermissions.clear();
  document.getElementById('current-user-label').textContent = '';
  showAuthForm(false);
}

function applyPermissionsToUI() {
  document.querySelectorAll('[data-permission], [data-page-permission]').forEach(element => {
    const elementPermissions = element.dataset.permission?.split(',') || [];
    const hasElementPermission = !elementPermissions.length ||
      elementPermissions.some(permission => currentPermissions.has(permission));
    const pagePermissions = element.dataset.pagePermission?.split(',') || [];
    const hasPagePermission = !pagePermissions.length ||
      ((currentPermissions.has('data.view') ||
        ((pagePermissions.includes('allocations.view') &&
          currentPermissions.has('allocations.view')) ||
         (pagePermissions.includes('users.view') &&
          currentPermissions.has('users.view')))) &&
        pagePermissions.some(permission => currentPermissions.has(permission)));
    element.hidden = !hasElementPermission || !hasPagePermission;
    if (!element.matches('section')) {
      element.style.display = element.hidden ? 'none' : '';
    }
  });
}

async function loadAdminPage() {
  const [usersResponse, rolesResponse] = await Promise.all([
    fetch('/api/admin/users'),
    fetch('/api/admin/roles')
  ]);
  if (!usersResponse.ok || !rolesResponse.ok) {
    alert('تعذر تحميل إعدادات المستخدمين والأدوار.');
    return;
  }
  const usersData = await usersResponse.json();
  const rolesData = await rolesResponse.json();
  const roleNames = new Map(rolesData.roles.map(role => [role.id, role.name]));
  const roleSelect = document.getElementById('admin-user-role');
  roleSelect.innerHTML = rolesData.roles.length
    ? rolesData.roles.map(role => `<option value="${escapeHtml(role.id)}">${escapeHtml(role.name)}</option>`).join('')
    : '<option value="">أنشئ دورًا أولًا</option>';
  roleSelect.disabled = !rolesData.roles.length;
  document.getElementById('admin-users-body').innerHTML = usersData.users.map(user => `
    <tr>
      <td><strong>${escapeHtml(user.username)}</strong></td>
      <td>${escapeHtml(roleNames.get(user.roleId) || 'غير معروف')}</td>
      <td><span class="badge ${user.active ? 'badge-success' : 'badge-danger'}">${user.active ? 'نشط' : 'موقوف'}</span></td>
      <td>${currentPermissions.has('users.edit') ? `<button class="btn btn-outline" onclick="editAdminUser('${escapeHtml(user.username)}','${escapeHtml(user.roleId)}',${user.active})"><i class="fa-solid fa-pen"></i> تعديل</button>` : ''}
      ${currentPermissions.has('users.delete') ? `<button class="btn btn-danger" onclick="deleteAdminUser('${escapeHtml(user.username)}')"><i class="fa-solid fa-trash"></i> حذف</button>` : ''}</td>
    </tr>`).join('');

  document.getElementById('admin-permission-options').innerHTML = `
    ${ROLE_MODULES.map(module => `
      <label class="admin-permission-card">
        <span>${escapeHtml(module.label)}</span>
        <select data-role-module="${module.key}" aria-label="مستوى صلاحية ${escapeHtml(module.label)}">
          <option value="none">بدون صلاحية</option>
          <option value="read">قراءة</option>
          <option value="edit">قراءة وتعديل</option>
          <option value="delete">قراءة وتعديل وحذف</option>
        </select>
      </label>`).join('')}`;
  const assignedUsers = new Map();
  usersData.users.forEach(user => assignedUsers.set(user.roleId, (assignedUsers.get(user.roleId) || 0) + 1));
  document.getElementById('admin-roles-list').innerHTML = rolesData.roles.map(role => `
    <div class="admin-role-item">
      <div class="admin-role-info">
        <strong>${escapeHtml(role.name)}</strong>
        <span>${assignedUsers.get(role.id) || 0} مستخدم · ${ROLE_MODULES.filter(module => roleModuleLevel(role.permissions, module.key) !== 'none').length} وحدات مفعّلة</span>
      </div>
      <div class="admin-role-actions">
        ${currentPermissions.has('users.edit') ? `<button class="btn btn-outline" onclick="editAdminRole('${escapeHtml(role.id)}')"><i class="fa-solid fa-pen"></i> تعديل</button>` : ''}
        ${currentPermissions.has('users.delete') ? `<button class="btn btn-danger" onclick="deleteAdminRole('${escapeHtml(role.id)}')"><i class="fa-solid fa-trash"></i> حذف</button>` : ''}
      </div>
    </div>`).join('');
  if (!rolesData.roles.length) {
    document.getElementById('admin-roles-list').innerHTML = '<p class="admin-empty-state">لا توجد أدوار بعد. أنشئ دورًا لتتمكن من إضافة المستخدمين.</p>';
  }
  if (!usersData.users.length) {
    document.getElementById('admin-users-body').innerHTML = '<tr><td class="admin-empty-state" colspan="4">لا يوجد مستخدمون إضافيون مسجلون.</td></tr>';
  }
  applyPermissionsToUI();
}

function rolePermissionsFromForm() {
  const permissions = [];
  let needsDataView = false;
  for (const module of ROLE_MODULES) {
    const level = document.querySelector(`[data-role-module="${module.key}"]`).value;
    if (level === 'none') continue;
    permissions.push(`${module.key}.${level}`);
    if (DATA_VIEW_REQUIRED_MODULES.has(module.key)) needsDataView = true;
  }
  if (document.getElementById('role-data-view').checked || needsDataView) permissions.push('data.view');
  return [...new Set(permissions)];
}

function roleModuleLevel(permissions, moduleKey) {
  if (moduleKey === 'allocations' && permissions.includes('courses.manage') &&
      !permissions.some(permission => permission.startsWith('allocations.'))) return 'delete';
  if (permissions.includes(`${moduleKey}.delete`) || permissions.includes(`${moduleKey}.manage`)) return 'delete';
  if (permissions.includes(`${moduleKey}.edit`)) return 'edit';
  if (permissions.includes(`${moduleKey}.read`)) return 'read';
  return 'none';
}

function resetAdminUserForm() {
  document.getElementById('admin-user-form').reset();
  document.getElementById('admin-user-original').value = '';
  document.getElementById('admin-user-active').checked = true;
  document.getElementById('admin-user-name').disabled = false;
  document.getElementById('admin-user-password').required = true;
}

function editAdminUser(username, roleId, active) {
  if (!hasPermission('users.edit')) return;
  document.getElementById('admin-user-original').value = username;
  document.getElementById('admin-user-name').value = username;
  document.getElementById('admin-user-name').disabled = true;
  document.getElementById('admin-user-role').value = roleId;
  document.getElementById('admin-user-active').checked = active;
  document.getElementById('admin-user-password').value = '';
  document.getElementById('admin-user-password').required = false;
}

async function saveAdminUser(event) {
  event.preventDefault();
  if (!hasPermission('users.edit')) return;
  const original = document.getElementById('admin-user-original').value;
  const username = document.getElementById('admin-user-name').value.trim();
  const password = document.getElementById('admin-user-password').value;
  if (!original && password.length < 12) {
    alert('كلمة المرور يجب ألا تقل عن 12 حرفًا.');
    return;
  }
  const response = await fetch('/api/admin/users', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'save', username, password, roleId: document.getElementById('admin-user-role').value,
      active: document.getElementById('admin-user-active').checked
    })
  });
  const result = await response.json();
  if (!response.ok) {
    alert(result.error || 'تعذر حفظ المستخدم.');
    return;
  }
  resetAdminUserForm();
  await loadAdminPage();
}

async function deleteAdminUser(username) {
  if (!hasPermission('users.delete')) return;
  if (!confirm(`حذف المستخدم ${username}؟`)) return;
  const response = await fetch('/api/admin/users', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'delete', username })
  });
  const result = await response.json();
  if (!response.ok) { alert(result.error || 'تعذر حذف المستخدم.'); return; }
  await loadAdminPage();
}

function resetAdminRoleForm() {
  document.getElementById('admin-role-form').reset();
  document.getElementById('admin-role-id').value = '';
  document.getElementById('role-data-view').checked = false;
  document.querySelectorAll('#admin-permission-options [data-role-module]').forEach(select => { select.value = 'none'; });
}

async function editAdminRole(roleId) {
  if (!hasPermission('users.edit')) return;
  const response = await fetch('/api/admin/roles');
  const data = await response.json();
  const role = data.roles.find(item => item.id === roleId);
  if (!role) return;
  document.getElementById('admin-role-id').value = role.id;
  document.getElementById('admin-role-name').value = role.name;
  document.getElementById('role-data-view').checked = role.permissions.includes('data.view');
  ROLE_MODULES.forEach(module => {
    document.querySelector(`[data-role-module="${module.key}"]`).value =
      roleModuleLevel(role.permissions, module.key);
  });
}

async function saveAdminRole(event) {
  event.preventDefault();
  if (!hasPermission('users.edit')) return;
  const permissions = rolePermissionsFromForm();
  const response = await fetch('/api/admin/roles', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id: document.getElementById('admin-role-id').value,
      name: document.getElementById('admin-role-name').value.trim(), permissions
    })
  });
  const result = await response.json();
  if (!response.ok) { alert(result.error || 'تعذر حفظ الدور.'); return; }
  resetAdminRoleForm();
  await loadAdminPage();
}

async function deleteAdminRole(id) {
  if (!hasPermission('users.delete')) return;
  if (!confirm('حذف هذا الدور؟')) return;
  const response = await fetch('/api/admin/roles', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'delete', id })
  });
  const result = await response.json();
  if (!response.ok) { alert(result.error || 'تعذر حذف الدور.'); return; }
  await loadAdminPage();
}

// Current state
let currentCourseIndex = null;

// Tab switcher
function switchTab(tabId) {
  const requiredPermission = TAB_PERMISSIONS[tabId];
  if (requiredPermission) {
    if (tabId !== 'admin' && tabId !== 'allocation' && !currentPermissions.has('data.view')) return;
    const hasTabPermission = Array.isArray(requiredPermission)
      ? requiredPermission.some(permission => currentPermissions.has(permission))
      : currentPermissions.has(requiredPermission);
    if (!hasTabPermission) return;
  }
  if (tabId === 'access-denied' && currentPermissions.has('data.view')) return;
  document.querySelectorAll('section').forEach(s => s.style.display = 'none');
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.bottom-bar-item').forEach(b => b.classList.remove('active'));

  const activeSec = document.getElementById('tab-' + tabId);
  if (activeSec) activeSec.style.display = 'block';

  const tabs = ['daily', 'courses', 'allocation', 'students', 'professors', 'workspace', 'expenses', 'closing', 'admin'];
  const idx = tabs.indexOf(tabId);
  if (idx !== -1) {
    if (document.querySelectorAll('.nav-item')[idx]) document.querySelectorAll('.nav-item')[idx].classList.add('active');
    if (document.querySelectorAll('.bottom-bar-item')[idx]) document.querySelectorAll('.bottom-bar-item')[idx].classList.add('active');
  }

  if (tabId === 'daily') loadDailyReport();
  if (tabId === 'courses') renderCoursesTable();
  if (tabId === 'allocation') renderAllocationPage();
  if (tabId === 'students') renderStudentsDirectory();
  if (tabId === 'professors') renderProfessorsTable();
  if (tabId === 'workspace') renderWorkspaceTable();
  if (tabId === 'expenses') {
    const dateInput = document.getElementById('expense-date');
    if (!dateInput.value) {
      const now = new Date();
      dateInput.value = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
    }
    renderExpensesTable();
  }
  if (tabId === 'closing') {
    setDefaultClosingDates();
    renderOwnersTable();
    renderClosings();
  }
  if (tabId === 'admin') loadAdminPage();
}

// ================= COURSE ALLOCATION =================
const ALLOCATION_DAYS = ['السبت', 'الأحد', 'الإثنين', 'الثلاثاء', 'الأربعاء', 'الخميس', 'الجمعة'];

function allocationId() {
  return window.crypto?.randomUUID ? window.crypto.randomUUID() : `${Date.now()}-${Math.random()}`;
}

function renderAllocationPage() {
  if (!Array.isArray(db.allocations)) db.allocations = [];
  if (!Array.isArray(db.rooms)) db.rooms = [];
  if (!db.roomColors || typeof db.roomColors !== 'object' || Array.isArray(db.roomColors)) db.roomColors = {};
  renderAllocationRoomFilters();
  renderAllocationMatrix();
  renderAllocationRooms();
}

const ROOM_COLOR_PALETTE = [
  '#2563eb', '#dc2626', '#16a34a', '#9333ea', '#ea580c', '#0891b2',
  '#be123c', '#4d7c0f', '#6d28d9', '#0f766e', '#b45309', '#475569',
  '#c026d3', '#0284c7', '#65a30d', '#e11d48', '#7c3aed', '#0d9488',
  '#ca8a04', '#334155', '#4f46e5', '#059669', '#c2410c', '#a21caf'
];

function randomAllocationIndex(max) {
  if (window.crypto?.getRandomValues) {
    const value = new Uint32Array(1);
    window.crypto.getRandomValues(value);
    return value[0] % max;
  }
  return Math.floor(Math.random() * max);
}

function generateRoomColor(usedColors) {
  const available = ROOM_COLOR_PALETTE.filter(color => !usedColors.has(color));
  if (available.length) return available[randomAllocationIndex(available.length)];
  let color;
  do {
    const channel = () => 48 + randomAllocationIndex(145);
    color = `#${[channel(), channel(), channel()].map(value => value.toString(16).padStart(2, '0')).join('')}`;
  } while (usedColors.has(color));
  return color;
}

function ensureAllocationRoomColors() {
  const existing = db.roomColors;
  const colors = Object.create(null);
  const usedColors = new Set();
  let changed = false;
  db.rooms.forEach(room => {
    const savedColor = existing[room];
    const color = typeof savedColor === 'string' && /^#[0-9a-fA-F]{6}$/.test(savedColor) &&
      !usedColors.has(savedColor.toLowerCase())
      ? savedColor
      : generateRoomColor(usedColors);
    colors[room] = color;
    usedColors.add(color.toLowerCase());
    if (savedColor !== color) changed = true;
  });
  if (Object.keys(existing).some(room => !db.rooms.includes(room))) changed = true;
  db.roomColors = colors;
  return changed;
}

function roomColor(room) {
  const color = db.roomColors?.[room];
  return typeof color === 'string' && /^#[0-9a-fA-F]{6}$/.test(color) ? color : '#64748b';
}

function renderAllocationRoomFilters() {
  const container = document.getElementById('allocation-room-filters');
  if (!container) return;
  if (!db.rooms.length) {
    container.innerHTML = '<span style="color:var(--text-muted);">أضف قاعات لتصفية الجدول حسب القاعة.</span>';
    return;
  }
  const allRoomsSelected = selectedAllocationRooms === null;
  container.innerHTML = `
    <span style="font-size:.86rem;font-weight:700;">عرض القاعات:</span>
    <button type="button" class="btn btn-outline" style="padding:.3rem .65rem;font-size:.8rem;" onclick="showAllAllocationRooms()">عرض كل القاعات</button>
    ${db.rooms.map((room, index) => `
      <label class="allocation-filter-option" style="--room-color:${roomColor(room)}">
        <input type="checkbox" ${allRoomsSelected || selectedAllocationRooms.has(room) ? 'checked' : ''}
          onchange="setAllocationRoomFilter(${index}, this.checked)">
        ${escapeHtml(room)}
      </label>`).join('')}`;
}

function showAllAllocationRooms() {
  selectedAllocationRooms = null;
  renderAllocationPage();
}

function setAllocationRoomFilter(index, checked) {
  const room = db.rooms[index];
  if (!room) return;
  if (selectedAllocationRooms === null) selectedAllocationRooms = new Set(db.rooms);
  if (checked) selectedAllocationRooms.add(room);
  else selectedAllocationRooms.delete(room);
  if (selectedAllocationRooms.size === db.rooms.length) selectedAllocationRooms = null;
  renderAllocationPage();
}

function renderAllocationMatrix() {
  const matrix = document.getElementById('allocation-matrix');
  if (!matrix) return;
  const slotsByDay = ALLOCATION_DAYS.map((_, day) => db.allocations
    .map((slot, index) => ({ slot, index }))
    .filter(item => Number(item.slot.day) === day)
    .filter(item => selectedAllocationRooms === null || selectedAllocationRooms.has(item.slot.room))
    .sort((a, b) => a.slot.startTime.localeCompare(b.slot.startTime)));

  matrix.innerHTML = ALLOCATION_DAYS.map((dayName, day) => {
    const slots = slotsByDay[day].map(({ slot, index }) => {
      const course = db.courses.find(item => item.name === slot.courseName);
      const students = course?.students || [];
      const period = slot.weekStart && slot.weekEnd
        ? `<div style="font-size:.76rem;color:var(--text-muted);margin-top:.3rem;">${escapeHtml(slot.weekStart)} — ${escapeHtml(slot.weekEnd)}</div>`
        : '';
      const roster = students.length
        ? `<ul class="allocation-students">${students.map(student => `<li>${escapeHtml(student.name || '')}</li>`).join('')}</ul>`
        : '<div class="allocation-students">لا يوجد طلاب مسجلون</div>';
      const actions = currentPermissions.has('allocations.edit') || currentPermissions.has('allocations.delete') ? `
        <div style="display:flex;gap:.4rem;margin-top:.55rem;">
          ${currentPermissions.has('allocations.edit') ? `<button class="btn btn-outline" style="padding:.2rem .45rem;font-size:.75rem;" onclick="editAllocation(${index})" title="تعديل التخصيص"><i class="fa-solid fa-pen"></i></button>` : ''}
          ${currentPermissions.has('allocations.delete') ? `<button class="btn btn-danger" style="padding:.2rem .45rem;font-size:.75rem;" onclick="deleteAllocation(${index})" title="حذف التخصيص"><i class="fa-solid fa-trash"></i></button>` : ''}
        </div>` : '';
      const colorStyle = `--room-color:${roomColor(slot.room)}`;
      return `
        <article class="allocation-slot" style="${colorStyle}">
          <strong>${escapeHtml(slot.courseName)}</strong>
          <div style="font-size:.86rem;margin-top:.25rem;"><i class="fa-regular fa-clock"></i> ${escapeHtml(slot.startTime)} - ${escapeHtml(slot.endTime)}</div>
          <div class="allocation-slot-room" style="${colorStyle};font-size:.86rem;"><i class="fa-solid fa-door-open"></i> ${escapeHtml(slot.room)}</div>
          ${period}
          <div style="font-size:.8rem;margin-top:.35rem;">${students.length} طالب</div>
          ${roster}${actions}
        </article>`;
    }).join('');
    return `<div class="allocation-day"><div class="allocation-day-title">${dayName}</div>${slots || '<span style="color:var(--text-muted);font-size:.82rem;">لا توجد حصص</span>'}</div>`;
  }).join('');
}

function renderAllocationRooms() {
  const container = document.getElementById('allocation-rooms-list');
  if (!container) return;
  container.innerHTML = db.rooms.length
    ? db.rooms.map((room, index) => `
      <span class="allocation-room-chip" style="--room-color:${roomColor(room)}">
        <span class="allocation-room-name">${escapeHtml(room)}</span>
        ${currentPermissions.has('allocations.delete') ? `<button type="button" class="btn btn-danger" style="padding:.15rem .4rem;font-size:.72rem;" onclick="deleteAllocationRoom(${index})" aria-label="حذف ${escapeHtml(room)}"><i class="fa-solid fa-xmark"></i></button>` : ''}
      </span>`).join('')
    : '<span style="color:var(--text-muted);">لم تتم إضافة قاعات بعد.</span>';
}

function addAllocationRoom(event) {
  event.preventDefault();
  requireAllocationPermission(() => {
    const input = document.getElementById('allocation-room-name');
    const room = input.value.trim();
    if (!room) return;
    if (db.rooms.some(existing => existing.toLocaleLowerCase() === room.toLocaleLowerCase())) {
      alert('هذه القاعة موجودة بالفعل.');
      return;
    }
    db.rooms.push(room);
    db.rooms.sort((a, b) => a.localeCompare(b, 'ar'));
    db.roomColors[room] = generateRoomColor(new Set(Object.values(db.roomColors).map(color => color.toLowerCase())));
    saveDB();
    input.value = '';
    renderAllocationPage();
  });
}

function deleteAllocationRoom(index) {
  if (!hasPermission('allocations.delete')) return;
  const room = db.rooms[index];
  if (!room) return;
  if (db.allocations.some(slot => slot.room === room)) {
    alert('لا يمكن حذف القاعة قبل نقل أو حذف التخصيصات المرتبطة بها.');
    return;
  }
  requireAllocationPermission(() => {
    if (!confirm(`حذف القاعة "${room}"؟`)) return;
    db.rooms.splice(index, 1);
    delete db.roomColors[room];
    if (selectedAllocationRooms !== null) selectedAllocationRooms.delete(room);
    saveDB();
    renderAllocationPage();
  });
}

function openAllocationModal(id = '') {
  if (!currentPermissions.has('allocations.manage')) {
    alert(`ليس لديك صلاحية ${PERMISSION_LABELS['allocations.manage']}.`);
    return;
  }
  if (!db.courses.length) {
    alert('أضف مادة أولاً قبل إنشاء تخصيص.');
    return;
  }
  if (!db.rooms.length) {
    alert('أضف قاعة واحدة على الأقل قبل إنشاء تخصيص.');
    return;
  }
  const courseSelect = document.getElementById('allocation-course');
  courseSelect.innerHTML = db.courses.map(course =>
    `<option value="${escapeHtml(course.name)}">${escapeHtml(course.name)}</option>`
  ).join('');
  document.getElementById('allocation-day').innerHTML = ALLOCATION_DAYS.map((day, index) =>
    `<option value="${index}">${day}</option>`
  ).join('');
  document.getElementById('allocation-room').innerHTML = db.rooms.map(room =>
    `<option value="${escapeHtml(room)}">${escapeHtml(room)}</option>`
  ).join('');
  document.getElementById('allocation-id').value = id;
  document.getElementById('allocation-modal-title').textContent = id ? 'تعديل تخصيص مادة' : 'إضافة تخصيص مادة';
  if (id) {
    const slot = db.allocations.find(item => item.id === id);
    if (!slot) return;
    courseSelect.value = slot.courseName;
    document.getElementById('allocation-day').value = String(slot.day);
    document.getElementById('allocation-start').value = slot.startTime;
    document.getElementById('allocation-end').value = slot.endTime;
    document.getElementById('allocation-room').value = slot.room;
    document.getElementById('allocation-week-start').value = slot.weekStart || '';
    document.getElementById('allocation-week-end').value = slot.weekEnd || '';
  } else {
    document.getElementById('allocation-start').value = '09:00';
    document.getElementById('allocation-end').value = '10:00';
    document.getElementById('allocation-week-start').value = '';
    document.getElementById('allocation-week-end').value = '';
  }
  document.getElementById('modal-allocation').classList.add('open');
}

function editAllocation(index) {
  const slot = db.allocations[index];
  if (slot) openAllocationModal(slot.id);
}

function allocationDateRangesOverlap(left, right) {
  const leftStart = left.weekStart || '0000-01-01';
  const rightStart = right.weekStart || '0000-01-01';
  const leftEnd = left.weekEnd || '9999-12-31';
  const rightEnd = right.weekEnd || '9999-12-31';
  return leftStart <= rightEnd && rightStart <= leftEnd;
}

function allocationConflicts(candidate, ignoredId = '') {
  return db.allocations.find(slot =>
    slot.id !== ignoredId &&
    Number(slot.day) === candidate.day &&
    slot.room === candidate.room &&
    candidate.startTime < slot.endTime &&
    slot.startTime < candidate.endTime &&
    allocationDateRangesOverlap(candidate, slot)
  );
}

function saveAllocation() {
  const id = document.getElementById('allocation-id').value;
  const slot = {
    id: id || allocationId(),
    courseName: document.getElementById('allocation-course').value,
    day: Number(document.getElementById('allocation-day').value),
    startTime: document.getElementById('allocation-start').value,
    endTime: document.getElementById('allocation-end').value,
    room: document.getElementById('allocation-room').value,
    weekStart: document.getElementById('allocation-week-start').value,
    weekEnd: document.getElementById('allocation-week-end').value
  };
  if (!slot.courseName || !Number.isInteger(slot.day) || slot.day < 0 || slot.day >= ALLOCATION_DAYS.length ||
      !slot.startTime || !slot.endTime || slot.startTime >= slot.endTime || !slot.room) {
    alert('أدخل المادة واليوم والقاعة ووقتًا صحيحًا (وقت النهاية بعد البداية).');
    return;
  }
  if (Boolean(slot.weekStart) !== Boolean(slot.weekEnd) ||
      (slot.weekStart && slot.weekStart > slot.weekEnd)) {
    alert('أدخل تاريخ بداية ونهاية الفترة معًا، واجعل البداية قبل النهاية أو مساوية لها.');
    return;
  }
  if (!db.courses.some(course => course.name === slot.courseName) || !db.rooms.includes(slot.room)) {
    alert('المادة أو القاعة المحددة لم تعد متاحة. حدّث الصفحة واختر من جديد.');
    return;
  }
  const conflict = allocationConflicts(slot, id);
  if (conflict) {
    alert(`تعارض في ${slot.room}: توجد حصة "${conflict.courseName}" في الوقت المتداخل نفسه يوم ${ALLOCATION_DAYS[slot.day]}.`);
    return;
  }

  requireAllocationPermission(() => {
    const index = db.allocations.findIndex(item => item.id === id);
    if (index >= 0) db.allocations[index] = slot;
    else db.allocations.push(slot);
    db.allocations.sort((a, b) => Number(a.day) - Number(b.day) || a.startTime.localeCompare(b.startTime));
    saveDB();
    closeModal('modal-allocation');
    renderAllocationPage();
  });
}

function deleteAllocation(index) {
  if (!hasPermission('allocations.delete')) return;
  const slot = db.allocations[index];
  if (!slot) return;
  requireAllocationPermission(() => {
    if (!confirm(`حذف تخصيص "${slot.courseName}" يوم ${ALLOCATION_DAYS[slot.day]}؟`)) return;
    db.allocations.splice(index, 1);
    saveDB();
    renderAllocationPage();
  });
}

// Set Today Date helper
function setTodayDate() {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth()+1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  const todayStr = `${y}-${m}-${d}`;
  document.getElementById('filter-date').value = todayStr;
  loadDailyReport();
}

function getCourseInstructorPercentage(course) {
  if (course.instructorPercentage !== undefined && Number.isFinite(Number(course.instructorPercentage))) {
    return Number(course.instructorPercentage);
  }

  const fee = Number(course.fee || course.students[0]?.fee || 2200);
  return getDefaultCourseInstructorPercentage(fee);
}

function getDefaultCourseInstructorPercentage(fee) {
  fee = Number(fee);
  const centerShare = fee >= 2500 ? 500 : fee <= 2200 ? 400 : Math.round(fee * (400 / 2200));
  return fee > 0 ? ((fee - centerShare) / fee) * 100 : 0;
}

function updateNewCourseInstructorPercentage() {
  const feeType = document.getElementById('new-course-fee-type').value;
  const fee = feeType === 'custom'
    ? Number(document.getElementById('custom-course-fee').value)
    : Number(feeType);
  document.getElementById('new-course-instructor-percentage').value =
    getDefaultCourseInstructorPercentage(fee).toFixed(2);
}

function roundCurrency(amount) {
  return Math.round((amount + Number.EPSILON) * 100) / 100;
}

// ================= DAILY REPORT LOGIC =================
function loadDailyReport() {
  const chosenDate = document.getElementById('filter-date').value || '2026-10-15';
  let totalSessionMoney = 0;
  let totalSessionCashMoney = 0;
  let totalSessionTransferMoney = 0;
  let totalCourseMoney = 0;
  let totalWSMoney = 0;
  let attendanceList = [];

  // 1. Workspace entries on that date
  db.workspace.forEach(w => {
    if (w.date === chosenDate) {
      totalWSMoney += parseFloat(w.total || 0);
      attendanceList.push({
        name: w.name,
        phone: w.phone || '-',
        type: 'ورك سبيس',
        status: 'جلسة عمل',
        amount: parseFloat(w.total || 0)
      });
    }
  });

  // 2. Course session attendances and 50 EGP payments on that date
  db.courses.forEach(c => {
    c.students.forEach(s => {
      if (s.sessions) {
        s.sessions.forEach(sess => {
          if (sess.date === chosenDate || (!sess.date && chosenDate === '2026-10-15' && sess.present)) {
            const paid50 = sess.paid50 ? 50 : 0;
            if (paid50 > 0) {
              totalSessionMoney += paid50;
              if (sess.paid50Method === 'transfer') totalSessionTransferMoney += paid50;
              else totalSessionCashMoney += paid50;
            }
            attendanceList.push({
              name: s.name,
              phone: s.phone || '-',
              type: c.name,
              status: sess.paid50
                ? `حضر ودفع 50ج ${sess.paid50Method === 'transfer' ? 'بالتحويل' : 'نقداً'}`
                : 'حاضر فقط',
              amount: paid50
            });
          }
        });
      }
    });
  });

  // 3. Course installments recorded
  if (db.dailyPayments) {
    db.dailyPayments.forEach(p => {
      if (p.date === chosenDate) {
        totalCourseMoney += parseFloat(p.amount);
        attendanceList.push({
          name: p.studentName,
          phone: p.phone || '-',
          type: p.courseName,
          status: 'دفعة اشتراك كورس',
          amount: parseFloat(p.amount)
        });
      }
    });
  }

  const grandTotal = totalSessionMoney + totalCourseMoney + totalWSMoney;
  document.getElementById('daily-total-income').innerText = grandTotal.toLocaleString() + ' ج.م';
  document.getElementById('daily-session-income').innerText = totalSessionMoney.toLocaleString() + ' ج.م';
  document.getElementById('daily-session-cash-income').innerText = totalSessionCashMoney.toLocaleString() + ' ج.م';
  document.getElementById('daily-session-transfer-income').innerText = totalSessionTransferMoney.toLocaleString() + ' ج.م';
  document.getElementById('daily-course-income').innerText = totalCourseMoney.toLocaleString() + ' ج.م';
  document.getElementById('daily-ws-income').innerText = totalWSMoney.toLocaleString() + ' ج.م';
  document.getElementById('daily-students-count').innerText = attendanceList.length + ' عملية / حضور';

  const tbody = document.getElementById('daily-table-body');
  if (attendanceList.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 2rem; color: #94a3b8;">لا توجد سجلات حضور أو دفع مسجلة في تاريخ ${chosenDate}</td></tr>`;
  } else {
    tbody.innerHTML = attendanceList.map(item => `
      <tr>
        <td style="font-weight: 700;">${item.name}</td>
        <td>${item.phone}</td>
        <td><span class="badge badge-primary">${item.type}</span></td>
        <td>${item.status}</td>
        <td style="font-weight: 700; color: #16a34a;">${item.amount} ج.م</td>
      </tr>
    `).join('');
  }
}

// ================= COURSES MANAGEMENT =================
function renderCoursesTable() {
  const query = (document.getElementById('course-search-input').value || '').toLowerCase();
  const tbody = document.getElementById('courses-table-body');
  
  let html = '';
  db.courses.forEach((c, idx) => {
    if (c.name.toLowerCase().includes(query)) {
      const studentCount = c.students.length;
      const fee = c.fee || c.students[0]?.fee || 2200;
      const instructorPercentage = getCourseInstructorPercentage(c);
      const hasCoursePayments = c.students.some(student =>
        student.paid || (student.sessions || []).some(session => session.paid50)
      );
      const hasAttendance = c.students.some(student => student.sessions?.length);
      const canDeleteCourse = currentPermissions.has('courses.delete') &&
        (!studentCount || currentPermissions.has('students.delete')) &&
        (!hasAttendance || currentPermissions.has('attendance.delete')) &&
        (!hasCoursePayments || currentPermissions.has('payments.delete'));
      let totalPaidCourse = 0;
      let totalSessionCashCollected = 0;
      let totalSessionTransferCollected = 0;

      c.students.forEach(s => {
        totalPaidCourse += (s.paid || 0);
        if (s.sessions) {
          s.sessions.forEach(sess => {
            if (sess.paid50) {
              if (sess.paid50Method === 'transfer') totalSessionTransferCollected += 50;
              else totalSessionCashCollected += 50;
            }
          });
        }
      });

      html += `
        <tr>
          <td style="font-weight: 800; font-size: 0.95rem;">${c.name}</td>
          <td>${c.professor || '-'}</td>
          <td><span class="badge badge-primary">${studentCount} طالب</span></td>
          <td>${fee} ج.م</td>
          <td>${instructorPercentage.toFixed(2)}%</td>
          <td style="color: #16a34a; font-weight: 700;">${totalPaidCourse.toLocaleString()} ج.م</td>
          <td style="color: #16a34a; font-weight: 700;">${totalSessionCashCollected.toLocaleString()} ج.م</td>
          <td style="color: #2563eb; font-weight: 700;">${totalSessionTransferCollected.toLocaleString()} ج.م</td>
          <td>
            <button class="btn btn-primary" style="padding: 0.4rem 0.8rem; font-size: 0.82rem;" onclick="openCourseSessionManager(${idx})">
              <i class="fa-solid fa-clipboard-user"></i> فتح الحصة والحضور
            </button>
            ${currentPermissions.has('courses.edit') ? `<button class="btn btn-outline" style="padding: 0.4rem 0.65rem; font-size: 0.82rem;" onclick="openEditCourseModalWithLock(${idx})" title="تعديل المادة"><i class="fa-solid fa-pen-to-square"></i></button>` : ''}
            ${canDeleteCourse ? `<button class="btn btn-danger" style="padding: 0.4rem 0.65rem; font-size: 0.82rem;" onclick="deleteCourseWithLock(${idx})" title="حذف المادة"><i class="fa-solid fa-trash"></i></button>` : ''}
          </td>
        </tr>
      `;
    }
  });
  tbody.innerHTML = html;
}

function filterCoursesList() {
  renderCoursesTable();
}

function deleteCourseWithLock(idx) {
  requireDeletePermission('courses.manage', () => {
    const course = db.courses[idx];
    if (!course) return;
    if (course.students.length && !currentPermissions.has('students.delete')) {
      alert(`ليس لديك صلاحية ${PERMISSION_LABELS['students.delete']}.`);
      return;
    }
    if (course.students.some(student => student.sessions?.length) && !currentPermissions.has('attendance.delete')) {
      alert(`ليس لديك صلاحية ${PERMISSION_LABELS['attendance.delete']}.`);
      return;
    }
    const hasPayments = course.students.some(student =>
      student.paid || (student.sessions || []).some(session => session.paid50)
    );
    if (hasPayments && !currentPermissions.has('payments.delete')) {
      alert(`ليس لديك صلاحية ${PERMISSION_LABELS['payments.delete']}.`);
      return;
    }
    const message = `هل أنت متأكد من حذف مادة "${course.name}"؟ سيتم حذف ${course.students.length} طالبًا وسجلات الحضور ورسوم الحصص المرتبطة بها. ستظل دفعات الكورس المسجلة في سجل الإيرادات.`;
    if (!confirm(message)) return;

    db.courses.splice(idx, 1);
    db.allocations = db.allocations.filter(slot => slot.courseName !== course.name);
    if (currentCourseIndex === idx) {
      document.getElementById('active-course-box').style.display = 'none';
      currentCourseIndex = null;
    } else if (currentCourseIndex !== null && currentCourseIndex > idx) {
      currentCourseIndex -= 1;
    }
    saveDB();
    renderCoursesTable();
    renderProfessorsTable();
    renderStudentsDirectory();
    loadDailyReport();
  });
}

function openCourseSessionManager(idx) {
  currentCourseIndex = idx;
  const course = db.courses[idx];
  document.getElementById('current-course-title').innerText = course.name;
  
  const now = new Date();
  const todayStr = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  document.getElementById('session-date-input').value = todayStr;

  document.getElementById('active-course-box').style.display = 'block';
  document.getElementById('active-course-box').scrollIntoView({ behavior: 'smooth' });
  renderCourseStudents(idx);
}

function closeCourseSession() {
  document.getElementById('active-course-box').style.display = 'none';
  currentCourseIndex = null;
  renderCoursesTable();
}

function renderCourseStudents(cIdx) {
  const course = db.courses[cIdx];
  const tbody = document.getElementById('course-students-body');
  const currentDate = document.getElementById('session-date-input').value;

  if (course.students.length === 0) {
    tbody.innerHTML = '<tr><td colspan="11" style="text-align:center; padding: 2rem;">لا يوجد طلاب مضافين حتى الآن، اضغط إضافة طالب للمادة</td></tr>';
    return;
  }

  let html = '';
  course.students.forEach((s, sIdx) => {
    const remaining = (s.fee || course.fee || 2200) - (s.paid || 0);
    const badgeRem = remaining <= 0 ? '<span class="badge badge-success">خالص</span>' : `<span class="badge badge-danger">${remaining} ج.م</span>`;

    const sessForDate = s.sessions ? s.sessions.find(x => x.date === currentDate) : null;
    const isAtt = sessForDate ? sessForDate.present : false;
    const isPaid50 = sessForDate ? sessForDate.paid50 : false;
    const paid50Method = isPaid50 ? (sessForDate.paid50Method || 'cash') : null;
    const canDeleteStudent = currentPermissions.has('students.delete') &&
      (!(s.sessions || []).length || currentPermissions.has('attendance.delete')) &&
      (!(s.paid || s.sessions?.some(session => session.paid50)) || currentPermissions.has('payments.delete'));

    html += `
      <tr>
        <td>${sIdx + 1}</td>
        <td style="font-weight: 700;">${s.name}</td>
        <td>${s.phone || '<span style="color:#94a3b8;">غير مسجل</span>'}</td>
        <td>${s.fee || db.courses[cIdx].fee || 2200} ج.م</td>
        <td style="color:#16a34a; font-weight:700;">${s.paid || 0} ج.م</td>
        <td>${badgeRem}</td>
        <td>
          ${currentPermissions.has('payments.edit') ? `<button class="btn btn-outline" style="padding: 0.3rem 0.6rem; font-size: 0.8rem;" onclick="openPayCourseModalWithLock(${sIdx})">
            <i class="fa-solid fa-hand-holding-dollar"></i> تسديد 🔒
          </button>` : ''}
        </td>
        <td style="text-align: center;">
          ${currentPermissions.has('attendance.edit') ? `<div class="check-toggle ${isAtt ? 'checked' : ''}" onclick="handleAttendanceClick(${sIdx}, ${isAtt})"><i class="fa-solid fa-check"></i></div>` : (isAtt ? 'حاضر' : 'غائب')}
        </td>
        <td style="text-align: center;">
          ${currentPermissions.has('payments.edit') && currentPermissions.has('attendance.edit') ? `<div class="session-payment-options" role="group" aria-label="طريقة دفع رسوم الحصة">
            <button type="button" class="session-payment-option cash ${paid50Method === 'cash' ? 'selected' : ''}" aria-pressed="${paid50Method === 'cash'}" onclick="handleSessionPay50Click(${sIdx}, 'cash')">نقداً</button>
            <button type="button" class="session-payment-option transfer ${paid50Method === 'transfer' ? 'selected' : ''}" aria-pressed="${paid50Method === 'transfer'}" onclick="handleSessionPay50Click(${sIdx}, 'transfer')">تحويل</button>
          </div>` : (isPaid50 ? (paid50Method === 'transfer' ? 'تحويل' : 'نقداً') : '—')}
        </td>
        <td>
          ${currentPermissions.has('students.edit') ? `<button class="btn btn-outline" style="padding: 0.3rem 0.6rem; font-size: 0.8rem; color: #2563eb;" title="تعديل الهاتف أو الاسم" onclick="openEditStudentModalWithLock(${sIdx})">
            <i class="fa-solid fa-pen-to-square"></i> تعديل
          </button>` : ''}
        </td>
        <td>
          ${canDeleteStudent ? `<button class="btn btn-danger" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;" onclick="deleteStudentFromCourseWithLock(${sIdx})">
            <i class="fa-solid fa-trash"></i>
          </button>` : ''}
        </td>
      </tr>
    `;
  });
  tbody.innerHTML = html;
}

// Attendance Click with Lock on Uncheck/Modification
function handleAttendanceClick(sIdx, isCurrentlyChecked) {
  requirePermission('attendance.manage', () => toggleAttendanceExecute(sIdx));
}

function toggleAttendanceExecute(sIdx) {
  if (!hasPermission('attendance.manage')) return;
  const course = db.courses[currentCourseIndex];
  const s = course.students[sIdx];
  const curDate = document.getElementById('session-date-input').value;
  if (!s.sessions) s.sessions = [];
  
  let sess = s.sessions.find(x => x.date === curDate);
  if (!sess) {
    sess = { date: curDate, present: true, paid50: false };
    s.sessions.push(sess);
  } else {
    sess.present = !sess.present;
  }
  saveDB();
  renderCourseStudents(currentCourseIndex);
  renderCoursesTable();
  renderStudentsDirectory();
  loadDailyReport();
}

// Session 50 EGP payment Click with Lock on Uncheck/Modification
function handleSessionPay50Click(sIdx, method) {
  requirePermission('attendance.manage', () => {
    requirePermission('payments.manage', () => toggleSessionPay50Execute(sIdx, method));
  });
}

function toggleSessionPay50Execute(sIdx, method) {
  if (!hasPermission('attendance.manage')) return;
  if (!hasPermission('payments.manage')) return;
  if (method !== 'cash' && method !== 'transfer') {
    alert('طريقة الدفع غير صحيحة');
    return;
  }
  const course = db.courses[currentCourseIndex];
  const s = course.students[sIdx];
  const curDate = document.getElementById('session-date-input').value;
  if (!s.sessions) s.sessions = [];

  let sess = s.sessions.find(x => x.date === curDate);
  if (!sess) {
    sess = { date: curDate, present: true, paid50: true, paid50Method: method };
    s.sessions.push(sess);
  } else {
    if (sess.paid50 && (sess.paid50Method || 'cash') === method) {
      sess.paid50 = false;
      delete sess.paid50Method;
    } else {
      sess.paid50 = true;
      sess.paid50Method = method;
      sess.present = true;
    }
  }
  saveDB();
  renderCourseStudents(currentCourseIndex);
  renderCoursesTable();
  renderStudentsDirectory();
  loadDailyReport();
}

// Payment modal with lock
function openPayCourseModalWithLock(sIdx) {
  requirePermission('payments.manage', () => {
    const s = db.courses[currentCourseIndex].students[sIdx];
    document.getElementById('pay-student-idx').value = sIdx;
    document.getElementById('pay-student-name').value = s.name;
    document.getElementById('pay-amount-input').value = '';
    document.getElementById('pay-date-input').value = document.getElementById('session-date-input').value;
    document.getElementById('modal-pay-course').classList.add('open');
  });
}

function confirmPaymentCourse() {
  if (!hasPermission('payments.manage')) return;
  const sIdx = document.getElementById('pay-student-idx').value;
  const amt = parseFloat(document.getElementById('pay-amount-input').value);
  const date = document.getElementById('pay-date-input').value;
  if (!amt || amt <= 0) {
    alert('يرجى إدخال مبلغ صحيح');
    return;
  }
  const s = db.courses[currentCourseIndex].students[sIdx];
  s.paid = (s.paid || 0) + amt;

  if (!db.dailyPayments) db.dailyPayments = [];
  db.dailyPayments.push({
    date: date,
    studentName: s.name,
    phone: s.phone,
    courseName: db.courses[currentCourseIndex].name,
    amount: amt,
    instructorPercentage: getCourseInstructorPercentage(db.courses[currentCourseIndex])
  });

  saveDB();
  closeModal('modal-pay-course');
  renderCourseStudents(currentCourseIndex);
  renderCoursesTable();
  renderProfessorsTable();
  renderStudentsDirectory();
  loadDailyReport();
  alert(`تم استلام وتسجيل ${amt} ج.م للطالب ${s.name} بنجاح!`);
}

// Delete student with lock
function deleteStudentFromCourseWithLock(sIdx) {
  requireDeletePermission('students.manage', () => {
    const student = db.courses[currentCourseIndex]?.students[sIdx];
    if (!student) return;
    if (student.sessions?.length && !hasPermission('attendance.delete')) return;
    if ((student.paid || student.sessions?.some(session => session.paid50)) &&
        !hasPermission('payments.delete')) return;
    if (confirm('هل أنت متأكد تماماً من حذف هذا الطالب من المادة؟')) {
      db.courses[currentCourseIndex].students.splice(sIdx, 1);
      saveDB();
      renderCourseStudents(currentCourseIndex);
      renderCoursesTable();
      renderProfessorsTable();
      renderStudentsDirectory();
    }
  });
}

// Add student modal with lock
function openAddStudentToCourseModalWithLock() {
  requirePermission('students.manage', () => {
    const course = db.courses[currentCourseIndex];
    document.getElementById('new-stu-name').value = '';
    document.getElementById('new-stu-phone').value = '';
    document.getElementById('new-stu-fee').value = course.fee || course.students[0]?.fee || 2200;
    document.getElementById('new-stu-paid').value = '0';
    document.getElementById('modal-add-student').classList.add('open');
  });
}

function saveNewStudentToCurrentCourse() {
  if (!hasPermission('students.manage')) return;
  const name = document.getElementById('new-stu-name').value.trim();
  const phone = document.getElementById('new-stu-phone').value.trim();
  const fee = parseFloat(document.getElementById('new-stu-fee').value);
  const paid = parseFloat(document.getElementById('new-stu-paid').value) || 0;
  if (paid > 0 && !hasPermission('payments.manage')) return;

  if (!name || !Number.isFinite(fee) || fee <= 0 || !Number.isFinite(paid) || paid < 0) {
    alert('يرجى إدخال اسم الطالب وسعر ومبلغ مدفوع صحيحين');
    return;
  }

  const curDate = document.getElementById('session-date-input').value;
  const newStudent = {
    name: name,
    phone: phone,
    fee: fee,
    paid: paid,
    sessions: currentPermissions.has('attendance.edit')
      ? [{ date: curDate, present: true, paid50: false }]
      : []
  };

  if (paid > 0) {
    if (!db.dailyPayments) db.dailyPayments = [];
    db.dailyPayments.push({
      date: curDate,
      studentName: name,
      phone: phone,
      courseName: db.courses[currentCourseIndex].name,
      amount: paid,
      instructorPercentage: getCourseInstructorPercentage(db.courses[currentCourseIndex])
    });
  }

  db.courses[currentCourseIndex].students.push(newStudent);
  saveDB();
  closeModal('modal-add-student');
  renderCourseStudents(currentCourseIndex);
  renderCoursesTable();
  renderProfessorsTable();
  renderStudentsDirectory();
  loadDailyReport();
  alert(`تمت إضافة الطالب ${name} وتسجيله بنجاح!`);
}

// ================= GLOBAL STUDENT DIRECTORY =================
function renderStudentsDirectory() {
  const query = (document.getElementById('global-student-search').value || '').trim().toLowerCase();
  const container = document.getElementById('students-directory-results');

  const studentMap = {};
  let totalSessionCashIncome = 0;
  let totalSessionTransferIncome = 0;
  db.courses.forEach(c => {
    c.students.forEach(s => {
      const key = (s.name + '___' + (s.phone || '')).toLowerCase();
      if (!studentMap[key]) {
        studentMap[key] = {
          name: s.name,
          phone: s.phone || '',
          courses: []
        };
      }
      studentMap[key].courses.push({
        courseName: c.name,
        courseIndex: db.courses.indexOf(c),
        studentIndex: c.students.indexOf(s),
        fee: s.fee || c.fee || 2200,
        paid: s.paid || 0,
        sessionsCount: s.sessions ? s.sessions.filter(x => x.present).length : 0,
        sessionCashIncome: s.sessions ? s.sessions.filter(x => x.paid50 && x.paid50Method !== 'transfer').length * 50 : 0,
        sessionTransferIncome: s.sessions ? s.sessions.filter(x => x.paid50 && x.paid50Method === 'transfer').length * 50 : 0
      });
      (s.sessions || []).forEach(session => {
        if (!session.paid50) return;
        if (session.paid50Method === 'transfer') totalSessionTransferIncome += 50;
        else totalSessionCashIncome += 50;
      });
    });
  });
  document.getElementById('students-session-cash-income').innerText = totalSessionCashIncome.toLocaleString() + ' ج.م';
  document.getElementById('students-session-transfer-income').innerText = totalSessionTransferIncome.toLocaleString() + ' ج.م';

  const students = Object.values(studentMap);
  const filtered = query ? students.filter(st => st.name.toLowerCase().includes(query) || st.phone.includes(query)) : students.slice(0, 30);

  if (filtered.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding: 2.5rem; color:#94a3b8;">لم يتم العثور على أي طالب بهذا الاسم أو الرقم</div>';
    return;
  }

  container.innerHTML = filtered.map(st => {
    const totalFee = st.courses.reduce((a, b) => a + b.fee, 0);
    const totalPaid = st.courses.reduce((a, b) => a + b.paid, 0);
    const totalRem = totalFee - totalPaid;

    return `
      <div style="border: 1px solid var(--border); border-radius: var(--radius); padding: 1.2rem; margin-bottom: 1rem; background: #fff;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.8rem;">
          <div>
            <h3 style="font-size: 1.15rem; font-weight: 800; color: var(--primary-dark);">${st.name}</h3>
            <span style="font-size: 0.85rem; color: var(--text-muted);"><i class="fa-solid fa-phone"></i> ${st.phone || 'بدون رقم'}</span>
          </div>
          <div style="text-align: left;">
            <span class="badge badge-primary">مسجل في ${st.courses.length} مواد</span>
            <div style="font-size: 0.85rem; margin-top: 4px;">
              المسدد: <b style="color:#16a34a;">${totalPaid} ج.م</b> | الباقي: <b style="color:#ef4444;">${totalRem} ج.م</b>
            </div>
          </div>
        </div>
        <div class="table-responsive">
          <table class="student-course-table" style="font-size: 0.85rem;">
            <thead>
              <tr style="background: #f1f5f9;">
                <th>المادة المسجلة</th>
                <th>سعر الكورس</th>
                <th>المبلغ المدفوع</th>
                <th>المتبقي عليه</th>
                <th>عدد الحصص الحاضرة</th>
                <th>مدفوع حصص نقداً</th>
                <th>مدفوع حصص تحويلاً</th>
                <th>إجراءات</th>
              </tr>
            </thead>
            <tbody>
              ${st.courses.map(co => `
                <tr>
                  <td style="font-weight: 700;">${co.courseName}</td>
                  <td>${co.fee} ج.م</td>
                  <td style="color:#16a34a; font-weight:700;">${co.paid} ج.م</td>
                  <td style="color:${co.fee-co.paid>0?'#ef4444':'#16a34a'}; font-weight:700;">${co.fee - co.paid} ج.م</td>
                  <td>${co.sessionsCount} حصة</td>
                  <td style="color:#16a34a; font-weight:700;">${co.sessionCashIncome.toLocaleString()} ج.م</td>
                  <td style="color:#2563eb; font-weight:700;">${co.sessionTransferIncome.toLocaleString()} ج.م</td>
                  <td>
                    ${currentPermissions.has('students.edit') ? `<button class="btn btn-outline" style="padding: 0.3rem 0.6rem; font-size: 0.8rem;" onclick="editStudentFromDirectory(${co.courseIndex}, ${co.studentIndex})">
                      <i class="fa-solid fa-pen-to-square"></i> تعديل
                    </button>` : ''}
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }).join('');
}

function editStudentFromDirectory(courseIndex, studentIndex) {
  switchTab('courses');
  openCourseSessionManager(courseIndex);
  openEditStudentModalWithLock(studentIndex);
}

// ================= PROFESSORS & SHARE LOGIC =================
function renderProfessorsTable() {
  const tbody = document.getElementById('professors-table-body');
  let html = '';

  db.courses.forEach(c => {
    const studentCount = c.students.length;
    const defaultFee = c.fee || c.students[0]?.fee || 2200;
    const instructorPercentage = getCourseInstructorPercentage(c);
    
    let totalTarget = 0;
    let totalActualPaid = 0;
    let centerShare = 0;
    let profShare = 0;

    c.students.forEach(s => {
      const fee = s.fee || defaultFee;
      totalTarget += fee;
      totalActualPaid += (s.paid || 0);
      const instructorAmount = roundCurrency(fee * instructorPercentage / 100);
      profShare += instructorAmount;
      centerShare += fee - instructorAmount;
    });
    centerShare = roundCurrency(centerShare);
    profShare = roundCurrency(profShare);

    html += `
      <tr>
        <td style="font-weight: 800;">${c.name}</td>
        <td>${c.professor || '-'}</td>
        <td>${defaultFee} ج.م</td>
        <td>${instructorPercentage.toFixed(2)}%</td>
        <td><span class="badge badge-primary">${studentCount} طالب</span></td>
        <td style="font-weight: 700;">${totalTarget.toLocaleString()} ج.م</td>
        <td style="color: #16a34a; font-weight: 700;">${totalActualPaid.toLocaleString()} ج.م</td>
        <td style="color: #2563eb; font-weight: 800;">${centerShare.toLocaleString()} ج.م</td>
        <td style="color: #d97706; font-weight: 800;">${profShare.toLocaleString()} ج.م</td>
      </tr>
    `;
  });

  tbody.innerHTML = html;
}

// ================= WORKSPACE LOGIC =================
function renderWorkspaceTable() {
  const tbody = document.getElementById('workspace-table-body');
  if (db.workspace.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding: 2rem;">لا توجد بيانات مسجلة في الورك سبيس</td></tr>';
    return;
  }
  tbody.innerHTML = db.workspace.slice().reverse().map((w, rIdx) => {
    const realIdx = db.workspace.length - 1 - rIdx;
    return `
      <tr>
        <td style="font-weight:700;">${w.date || '2026-10-15'}</td>
        <td style="font-weight:800;">${w.name}</td>
        <td>${w.phone || '-'}</td>
        <td>${w.time_in || '-'}</td>
        <td>${w.time_out || '-'}</td>
        <td>${w.extra_item || '-'}</td>
        <td style="color:#16a34a; font-weight:800;">${w.total ?? 60} ج.م</td>
        <td>
          ${currentPermissions.has('workspace.edit') ? `<button class="btn btn-outline" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="openEditWorkspaceEntryWithLock(${realIdx})" title="تعديل السجل">
            <i class="fa-solid fa-pen-to-square"></i>
          </button>` : ''}
          ${currentPermissions.has('workspace.delete') ? `<button class="btn btn-danger" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="deleteWorkspaceEntryWithLock(${realIdx})">
            <i class="fa-solid fa-trash"></i>
          </button>` : ''}
        </td>
      </tr>
    `;
  }).join('');
}

function openAddWorkspaceModal() {
  if (!hasPermission('workspace.edit')) return;
  const now = new Date();
  const todayStr = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  document.getElementById('ws-new-date').value = todayStr;
  document.getElementById('ws-new-name').value = '';
  document.getElementById('ws-new-phone').value = '';
  document.getElementById('ws-new-time-in').value = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
  document.getElementById('ws-new-total').value = '60';
  document.getElementById('ws-new-extra').value = '';
  document.getElementById('modal-add-workspace').classList.add('open');
}

function saveNewWorkspaceEntry() {
  if (!hasPermission('workspace.manage')) return;
  const date = document.getElementById('ws-new-date').value;
  const name = document.getElementById('ws-new-name').value.trim();
  const phone = document.getElementById('ws-new-phone').value.trim();
  const time_in = document.getElementById('ws-new-time-in').value;
  const total = Number(document.getElementById('ws-new-total').value);
  const extra = document.getElementById('ws-new-extra').value.trim();

  if (!date || !name || !Number.isFinite(total) || total < 0) {
    alert('يرجى إدخال تاريخ واسم ومبلغ صحيحين');
    return;
  }

  db.workspace.push({
    date: date,
    name: name,
    phone: phone,
    time_in: time_in,
    time_out: '',
    extra_item: extra,
    total: total
  });

  saveDB();
  closeModal('modal-add-workspace');
  renderWorkspaceTable();
  loadDailyReport();
  alert(`تم تسجيل دخول ${name} للورك سبيس بنجاح!`);
}

function deleteWorkspaceEntryWithLock(idx) {
  requireDeletePermission('workspace.manage', () => {
    if (confirm('هل أنت متأكد من حذف هذا السجل؟')) {
      db.workspace.splice(idx, 1);
      saveDB();
      renderWorkspaceTable();
      loadDailyReport();
    }
  });
}

function openEditWorkspaceEntryWithLock(idx) {
  requirePermission('workspace.manage', () => {
    const entry = db.workspace[idx];
    if (!entry) return;
    document.getElementById('edit-ws-idx').value = idx;
    document.getElementById('edit-ws-date').value = entry.date || '';
    document.getElementById('edit-ws-name').value = entry.name || '';
    document.getElementById('edit-ws-phone').value = entry.phone || '';
    document.getElementById('edit-ws-time-in').value = entry.time_in || '';
    document.getElementById('edit-ws-time-out').value = entry.time_out || '';
    document.getElementById('edit-ws-total').value = entry.total ?? 60;
    document.getElementById('edit-ws-extra').value = entry.extra_item || '';
    document.getElementById('modal-edit-workspace').classList.add('open');
  });
}

function saveEditedWorkspaceEntry() {
  if (!hasPermission('workspace.manage')) return;
  const idx = Number(document.getElementById('edit-ws-idx').value);
  const date = document.getElementById('edit-ws-date').value;
  const name = document.getElementById('edit-ws-name').value.trim();
  const total = Number(document.getElementById('edit-ws-total').value);

  if (!db.workspace[idx] || !date || !name || !Number.isFinite(total) || total < 0) {
    alert('يرجى إدخال تاريخ واسم ومبلغ صحيحين');
    return;
  }

  db.workspace[idx] = {
    ...db.workspace[idx],
    date,
    name,
    phone: document.getElementById('edit-ws-phone').value.trim(),
    time_in: document.getElementById('edit-ws-time-in').value,
    time_out: document.getElementById('edit-ws-time-out').value,
    total,
    extra_item: document.getElementById('edit-ws-extra').value.trim()
  };

  saveDB();
  closeModal('modal-edit-workspace');
  renderWorkspaceTable();
  loadDailyReport();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
}

function saveExpense(event) {
  event.preventDefault();
  if (!hasPermission('expenses.manage')) return;
  const date = document.getElementById('expense-date').value;
  const name = document.getElementById('expense-name').value.trim();
  const amount = Number(document.getElementById('expense-amount').value);
  const type = document.getElementById('expense-type').value.trim();

  if (!date || !name || !type || !Number.isFinite(amount) || amount <= 0) {
    alert('يرجى إدخال التاريخ واسم المصروف والنوع ومبلغ صحيح أكبر من صفر');
    return;
  }

  db.expenses.push({ date, name, amount, type });
  saveDB();
  document.getElementById('expense-form').reset();
  document.getElementById('expense-date').value = date;
  renderExpensesTable();
}

function renderExpensesTable() {
  const tbody = document.getElementById('expenses-table-body');
  const expenses = db.expenses || [];
  const total = expenses.reduce((sum, expense) => sum + Number(expense.amount || 0), 0);
  document.getElementById('expenses-total').innerText = `إجمالي المصروفات: ${total.toLocaleString()} ج.م`;

  if (!expenses.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem; color:#94a3b8;">لا توجد مصروفات مسجلة حتى الآن</td></tr>';
    return;
  }

  tbody.innerHTML = expenses.map((expense, index) => ({ expense, index }))
    .sort((a, b) => String(b.expense.date || '').localeCompare(String(a.expense.date || '')) || b.index - a.index)
    .map(({ expense, index }) => `
      <tr>
        <td>${escapeHtml(expense.date || '')}</td>
        <td style="font-weight:700;">${escapeHtml(expense.name || '')}</td>
        <td><span class="badge badge-warning">${escapeHtml(expense.type || '')}</span></td>
        <td style="color:#dc2626; font-weight:800;">${Number(expense.amount || 0).toLocaleString()} ج.م</td>
        <td>
          ${currentPermissions.has('expenses.delete') ? `<button class="btn btn-danger" style="padding:0.25rem 0.6rem; font-size:0.8rem;" onclick="deleteExpenseWithLock(${index})" title="حذف المصروف">
            <i class="fa-solid fa-trash"></i> حذف
          </button>` : ''}
        </td>
      </tr>
    `).join('');
}

function deleteExpenseWithLock(index) {
  requireDeletePermission('expenses.manage', () => {
    if (!db.expenses[index] || !confirm('هل أنت متأكد من حذف هذا المصروف؟')) return;
    db.expenses.splice(index, 1);
    saveDB();
    renderExpensesTable();
  });
}

function setDefaultClosingDates() {
  const now = new Date();
  const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  const firstOfMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;
  const startInput = document.getElementById('closing-start-date');
  const endInput = document.getElementById('closing-end-date');
  if (!startInput.value) startInput.value = firstOfMonth;
  if (!endInput.value) endInput.value = today;
}

function addOwner(event) {
  event.preventDefault();
  const name = document.getElementById('owner-name').value.trim();
  const percentage = Number(document.getElementById('owner-percentage').value);
  const totalPercentage = db.owners.reduce((sum, owner) => sum + Number(owner.percentage || 0), 0);
  if (!name || !Number.isFinite(percentage) || percentage <= 0 || totalPercentage + percentage > 100.000001) {
    alert('أدخل اسم مالك ونسبة صحيحة. يجب ألا يتجاوز مجموع نسب الملاك 100%.');
    return;
  }

  requirePermission('closing.manage', () => {
    db.owners.push({
      id: window.crypto?.randomUUID ? window.crypto.randomUUID() : `${Date.now()}-${Math.random()}`,
      name,
      percentage
    });
    saveDB();
    document.getElementById('owner-form').reset();
    renderOwnersTable();
    renderClosings();
  });
}

function renderOwnersTable() {
  const tbody = document.getElementById('owners-table-body');
  const owners = db.owners || [];
  if (!owners.length) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding:1.5rem; color:#94a3b8;">أضف الملاك ونسبهم قبل إنشاء أول إقفال</td></tr>';
    return;
  }
  const totalPercentage = owners.reduce((sum, owner) => sum + Number(owner.percentage || 0), 0);
  tbody.innerHTML = owners.map((owner, index) => `
    <tr>
      <td style="font-weight:700;">${escapeHtml(owner.name)}</td>
      <td>${currentPermissions.has('closing.edit')
        ? `<input type="number" id="owner-rate-${index}" min="0.01" max="100" step="0.01" value="${Number(owner.percentage)}" aria-label="نسبة ${escapeHtml(owner.name)}">`
        : `${Number(owner.percentage).toFixed(2)}%`}</td>
      <td>
        ${currentPermissions.has('closing.edit') ? `<button class="btn btn-outline" style="padding:0.25rem 0.6rem; font-size:0.8rem;" onclick="updateOwnerPercentage(${index})" title="حفظ النسبة"><i class="fa-solid fa-check"></i></button>` : ''}
        ${currentPermissions.has('closing.delete') ? `<button class="btn btn-danger" style="padding:0.25rem 0.6rem; font-size:0.8rem;" onclick="deleteOwnerWithLock(${index})" title="حذف المالك"><i class="fa-solid fa-trash"></i></button>` : ''}
      </td>
    </tr>
  `).join('') + `
    <tr>
      <td style="font-weight:800;">إجمالي نسب الملاك</td>
      <td colspan="2" style="font-weight:800; color:${totalPercentage > 100 ? '#dc2626' : '#1e3a8a'};">${totalPercentage.toFixed(2)}% — المتبقي للمركز ${(100 - totalPercentage).toFixed(2)}%</td>
    </tr>
  `;
}

function updateOwnerPercentage(index) {
  const owner = db.owners[index];
  const percentage = Number(document.getElementById(`owner-rate-${index}`).value);
  const otherOwnersPercentage = db.owners.reduce((sum, item, itemIndex) =>
    sum + (itemIndex === index ? 0 : Number(item.percentage || 0)), 0);
  if (!owner || !Number.isFinite(percentage) || percentage <= 0 || otherOwnersPercentage + percentage > 100.000001) {
    alert('يجب أن تكون نسبة المالك أكبر من صفر وألا يتجاوز مجموع النسب 100%.');
    renderOwnersTable();
    return;
  }

  requirePermission('closing.manage', () => {
    owner.percentage = percentage;
    saveDB();
    renderOwnersTable();
  });
}

function deleteOwnerWithLock(index) {
  requireDeletePermission('closing.manage', () => {
    if (!db.owners[index] || !confirm('سيبقى اسم المالك وتوزيعه محفوظين في الإقفالات السابقة. هل تريد حذف المالك من الإقفالات المستقبلية؟')) return;
    db.owners.splice(index, 1);
    saveDB();
    renderOwnersTable();
  });
}

function calculateClosing(startDate, endDate) {
  if (!startDate || !endDate || startDate > endDate) {
    throw new Error('حدد فترة صحيحة: تاريخ البداية يجب ألا يأتي بعد تاريخ النهاية.');
  }

  const courseByName = new Map(db.courses.map(course => [course.name, course]));
  let courseGross = 0;
  let instructorShare = 0;
  (db.dailyPayments || []).forEach(payment => {
    if (!payment.date || payment.date < startDate || payment.date > endDate) return;
    const amount = Number(payment.amount || 0);
    const course = courseByName.get(payment.courseName);
    const rate = payment.instructorPercentage !== undefined
      ? Number(payment.instructorPercentage)
      : course ? getCourseInstructorPercentage(course) : 0;
    if (!Number.isFinite(amount) || amount < 0 || !Number.isFinite(rate) || rate < 0 || rate > 100) {
      throw new Error('توجد دفعة كورس بمبلغ أو نسبة معيد غير صالحة. صحح البيانات قبل الإقفال.');
    }
    courseGross += amount;
    instructorShare += amount * rate / 100;
  });
  const collectedCourseCenter = roundCurrency(courseGross - instructorShare);

  let sessionIncome = 0;
  (db.courses || []).forEach(course => {
    (course.students || []).forEach(student => {
      (student.sessions || []).forEach(session => {
      if (session.date && session.date >= startDate && session.date <= endDate && session.paid50) {
          sessionIncome += 50;
        }
      });
    });
  });

  const workspaceIncome = (db.workspace || []).reduce((sum, item) =>
    item.date && item.date >= startDate && item.date <= endDate ? sum + Number(item.total || 0) : sum, 0);
  const expenses = (db.expenses || []).reduce((sum, item) =>
    item.date && item.date >= startDate && item.date <= endDate ? sum + Number(item.amount || 0) : sum, 0);
  const totalIncome = roundCurrency(collectedCourseCenter + sessionIncome + workspaceIncome);
  const netProfit = roundCurrency(totalIncome - expenses);
  const ownersPercentage = db.owners.reduce((sum, owner) => sum + Number(owner.percentage || 0), 0);
  if (ownersPercentage > 100.000001) {
    throw new Error('مجموع نسب الملاك يتجاوز 100%. صحح النسب قبل حساب الإقفال.');
  }

  const distributableProfit = Math.max(0, netProfit);
  const ownerDistributions = db.owners.map(owner => ({
    ownerId: owner.id,
    name: owner.name,
    percentage: Number(owner.percentage),
    amount: roundCurrency(distributableProfit * Number(owner.percentage) / 100)
  }));
  const totalOwnerDistribution = roundCurrency(ownerDistributions.reduce((sum, owner) => sum + owner.amount, 0));

  return {
    startDate,
    endDate,
    courseGross: roundCurrency(courseGross),
    instructorShare: roundCurrency(instructorShare),
    courseIncome: collectedCourseCenter,
    sessionIncome: roundCurrency(sessionIncome),
    workspaceIncome: roundCurrency(workspaceIncome),
    totalIncome,
    expenses: roundCurrency(expenses),
    netProfit,
    ownersPercentage: roundCurrency(ownersPercentage),
    ownerDistributions: ownerDistributions.map(owner => ({
      ...owner,
      status: owner.amount > 0 ? 'unpaid' : 'paid',
      distributionDate: ''
    })),
    retainedProfit: roundCurrency(netProfit - totalOwnerDistribution)
  };
}

function renderClosingSummary(closing) {
  const summaryRows = [
    ['حصة المركز من تحصيل الكورسات', closing.courseIncome],
    ['دخل الحصص المحصل', closing.sessionIncome],
    ['دخل الورك سبيس', closing.workspaceIncome],
    ['إجمالي دخل المركز', closing.totalIncome],
    ['المصروفات', -closing.expenses],
    ['صافي ربح / خسارة الفترة', closing.netProfit],
    ['إجمالي مستحقات الملاك', closing.ownerDistributions.reduce((sum, owner) => sum + owner.amount, 0)],
    ['الربح المحتجز للمركز', closing.retainedProfit]
  ];
  return `
    <div class="table-responsive">
      <table>
        <tbody>${summaryRows.map(([label, amount]) => `
          <tr><th>${label}</th><td style="font-weight:800;">${Number(amount).toLocaleString()} ج.م</td></tr>
        `).join('')}</tbody>
      </table>
    </div>
  `;
}

function previewClosing() {
  try {
    const result = calculateClosing(
      document.getElementById('closing-start-date').value,
      document.getElementById('closing-end-date').value
    );
    const preview = document.getElementById('closing-preview');
    preview.innerHTML = `
      ${renderClosingSummary(result)}
      <p style="font-size:0.82rem; color:var(--text-muted); margin-top:0.8rem;">
        حصة المعيد المحتسبة من التحصيلات: ${result.instructorShare.toLocaleString()} ج.م.
        هذه معاينة فقط؛ إنشاء الإقفال يحفظ لقطة ثابتة للفترة.
      </p>
    `;
    preview.style.display = 'block';
  } catch (error) {
    alert(error.message);
  }
}

function createClosingWithLock() {
  let snapshot;
  try {
    snapshot = calculateClosing(
      document.getElementById('closing-start-date').value,
      document.getElementById('closing-end-date').value
    );
  } catch (error) {
    alert(error.message);
    return;
  }
  if (!db.owners.length) {
    alert('أضف مالكاً ونسبته قبل إنشاء الإقفال.');
    return;
  }
  const overlaps = db.closings.some(closing =>
    snapshot.startDate <= closing.endDate && snapshot.endDate >= closing.startDate);
  if (overlaps) {
    alert('تتداخل هذه الفترة مع إقفال محفوظ. اختر فترة أخرى لتجنب احتساب الإيرادات أو المصروفات مرتين.');
    return;
  }

  requirePermission('closing.manage', () => {
    const now = new Date();
    snapshot.id = window.crypto?.randomUUID ? window.crypto.randomUUID() : `${Date.now()}-${Math.random()}`;
    snapshot.createdAt = now.toISOString();
    snapshot.status = 'open';
    snapshot.closedAt = '';
    db.closings.push(snapshot);
    saveDB();
    document.getElementById('closing-preview').style.display = 'none';
    renderClosings();
  });
}

function markOwnerDistributionPaid(closingIndex, ownerIndex) {
  const closing = db.closings[closingIndex];
  const distribution = closing?.ownerDistributions[ownerIndex];
  if (!closing || closing.status !== 'open' || !distribution || distribution.status === 'paid') return;
  const dateInput = document.getElementById(`distribution-date-${closingIndex}-${ownerIndex}`);
  const date = dateInput.value;
  if (!date) {
    alert('حدد تاريخ توزيع حصة المالك أولاً.');
    return;
  }

  requirePermission('closing.manage', () => {
    distribution.status = 'paid';
    distribution.distributionDate = date;
    saveDB();
    renderClosings();
  });
}

function closeFinancialPeriodWithLock(closingIndex) {
  const closing = db.closings[closingIndex];
  if (!closing || closing.status !== 'open') return;
  if (closing.ownerDistributions.some(distribution => distribution.status !== 'paid')) {
    alert('سجّل توزيع جميع حصص الملاك قبل إقفال الفترة.');
    return;
  }
  requirePermission('closing.manage', () => {
    closing.status = 'closed';
    closing.closedAt = new Date().toISOString();
    saveDB();
    renderClosings();
  });
}

function renderClosings() {
  const container = document.getElementById('closings-list');
  const closings = db.closings || [];
  if (!closings.length) {
    container.innerHTML = '<p style="text-align:center; padding:1.5rem; color:#94a3b8;">لا توجد إقفالات محفوظة. اختر فترة وأضف الملاك لإنشاء أول إقفال.</p>';
    return;
  }

  container.innerHTML = closings.slice().reverse().map((closing, reverseIndex) => {
    const closingIndex = closings.length - 1 - reverseIndex;
    const closed = closing.status === 'closed';
    const distributions = closing.ownerDistributions.map((owner, ownerIndex) => `
      <tr>
        <td style="font-weight:700;">${escapeHtml(owner.name)}</td>
        <td>${Number(owner.percentage).toFixed(2)}%</td>
        <td>${Number(owner.amount).toLocaleString()} ج.م</td>
        <td>
          ${owner.status === 'paid'
            ? `<span class="badge badge-success">تم التوزيع ${owner.distributionDate ? `في ${escapeHtml(owner.distributionDate)}` : ''}</span>`
            : currentPermissions.has('closing.edit')
              ? `<input type="date" id="distribution-date-${closingIndex}-${ownerIndex}" aria-label="تاريخ توزيع حصة ${escapeHtml(owner.name)}">
                 <button class="btn btn-success" style="padding:0.25rem 0.6rem; font-size:0.8rem;" onclick="markOwnerDistributionPaid(${closingIndex}, ${ownerIndex})">تسجيل التوزيع</button>`
              : '<span class="badge badge-warning">لم يتم التوزيع</span>'}
        </td>
      </tr>
    `).join('');

    return `
      <article class="box" style="border:1px solid var(--border);">
        <div class="box-header">
          <div>
            <div class="box-title">الفترة: ${escapeHtml(closing.startDate)} — ${escapeHtml(closing.endDate)}</div>
            <span class="badge ${closed ? 'badge-success' : 'badge-warning'}">${closed ? `مغلق بتاريخ ${escapeHtml(closing.closedAt.slice(0, 10))}` : 'مفتوح - بانتظار التوزيع والإقفال'}</span>
          </div>
        </div>
        ${renderClosingSummary(closing)}
        <h4 style="margin:1rem 0 0.5rem;">توزيعات الملاك</h4>
        <div class="table-responsive">
          <table>
            <thead><tr><th>المالك</th><th>النسبة</th><th>الحصة</th><th>تاريخ وحالة التوزيع</th></tr></thead>
            <tbody>${distributions || '<tr><td colspan="4">لا توجد حصص ملاك في هذا الإقفال</td></tr>'}</tbody>
          </table>
        </div>
        ${closed || !currentPermissions.has('closing.edit') ? '' : `<div style="text-align:left; margin-top:1rem;"><button class="btn btn-primary" onclick="closeFinancialPeriodWithLock(${closingIndex})"><i class="fa-solid fa-lock"></i> اعتماد وإقفال الفترة</button></div>`}
      </article>
    `;
  }).join('');
}

// Modal Helpers
function closeModal(id) {
  document.getElementById(id).classList.remove('open');
}

// Add New Course Modal with Lock
function openAddCourseModalWithLock() {
  requirePermission('courses.manage', () => {
    document.getElementById('new-course-name').value = '';
    document.getElementById('new-course-prof').value = '';
    document.getElementById('new-course-fee-type').value = '2200';
    document.getElementById('custom-course-fee').value = '2200';
    document.getElementById('custom-fee-div').style.display = 'none';
    document.getElementById('new-course-instructor-percentage').value = getDefaultCourseInstructorPercentage(2200).toFixed(2);
    document.getElementById('modal-add-course').classList.add('open');
  });
}

function openEditCourseModalWithLock(idx) {
  requirePermission('courses.manage', () => {
    const course = db.courses[idx];
    if (!course) return;
    document.getElementById('edit-course-idx').value = idx;
    document.getElementById('edit-course-name').value = course.name || '';
    document.getElementById('edit-course-prof').value = course.professor || '';
    document.getElementById('edit-course-fee').value = course.fee || course.students[0]?.fee || 2200;
    document.getElementById('edit-course-instructor-percentage').value = getCourseInstructorPercentage(course).toFixed(2);
    document.getElementById('modal-edit-course').classList.add('open');
  });
}

function saveEditedCourse() {
  if (!hasPermission('courses.manage')) return;
  const idx = Number(document.getElementById('edit-course-idx').value);
  const course = db.courses[idx];
  const name = document.getElementById('edit-course-name').value.trim();
  const fee = Number(document.getElementById('edit-course-fee').value);
  const instructorPercentage = Number(document.getElementById('edit-course-instructor-percentage').value);
  if (!course || !name || !Number.isFinite(fee) || fee <= 0 || !Number.isFinite(instructorPercentage) || instructorPercentage < 0 || instructorPercentage > 100) {
    alert('يرجى إدخال اسم المادة وسعر صحيح ونسبة معيد من 0 إلى 100');
    return;
  }

  const oldName = course.name;
  if (oldName !== name && db.dailyPayments.some(payment => payment.courseName === oldName) &&
      !hasPermission('payments.manage')) return;
  course.name = name;
  course.professor = document.getElementById('edit-course-prof').value.trim();
  course.fee = fee;
  course.instructorPercentage = instructorPercentage;
  db.dailyPayments.forEach(payment => {
    if (payment.courseName === oldName) payment.courseName = name;
  });
  db.allocations.forEach(slot => {
    if (slot.courseName === oldName) slot.courseName = name;
  });
  renderAllocationPage();
  saveDB();
  closeModal('modal-edit-course');
  renderCoursesTable();
  renderProfessorsTable();
  renderStudentsDirectory();
  loadDailyReport();
  if (currentCourseIndex === idx) {
    document.getElementById('current-course-title').innerText = course.name;
    renderCourseStudents(idx);
  }
}

function saveNewCourse() {
  if (!hasPermission('courses.manage')) return;
  const name = document.getElementById('new-course-name').value.trim();
  const feeType = document.getElementById('new-course-fee-type').value;
  let fee = parseFloat(feeType);
  if (feeType === 'custom') {
    fee = parseFloat(document.getElementById('custom-course-fee').value);
  }
  const instructorPercentage = Number(document.getElementById('new-course-instructor-percentage').value);

  if (!name || !Number.isFinite(fee) || fee <= 0 || !Number.isFinite(instructorPercentage) || instructorPercentage < 0 || instructorPercentage > 100) {
    alert('يرجى إدخال اسم المادة وسعر صحيح ونسبة معيد من 0 إلى 100');
    return;
  }

  db.courses.push({
    name: name,
    professor: document.getElementById('new-course-prof').value.trim(),
    fee: fee,
    instructorPercentage,
    students: []
  });

  saveDB();
  closeModal('modal-add-course');
  renderCoursesTable();
  renderProfessorsTable();
  alert(`تمت إضافة المادة ${name} بنجاح!`);
}

// ================= BACKUP & EXPORT/IMPORT =================
async function exportDataBackup() {
  if (!currentPermissions.has('backups.view')) {
    alert('ليس لديك صلاحية إدارة النسخ الاحتياطية.');
    return;
  }
  try {
    const response = await fetch('/api/data/export');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'تعذر تحميل النسخة الاحتياطية.');
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `asia_center_backup_${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    alert(error.message || 'تعذر تحميل النسخة الاحتياطية.');
  }
}

function sendBackupToEmail() {
  if (!hasPermission('backups.edit')) return;
  const email = prompt('أدخل عنوان البريد الإلكتروني الذي تريد إرسال النسخة الاحتياطية إليه:');
  if (email === null) return;

  const recipient = email.trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient)) {
    alert('يرجى إدخال عنوان بريد إلكتروني صحيح.');
    return;
  }

  requirePermission('backups.edit', () => {
    deliverBackupEmail(recipient);
  });
}

async function deliverBackupEmail(recipient) {
  try {
    const response = await fetch('/api/send-backup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipient })
    });
    const result = await response.json();
    if (!response.ok || !result.ok) {
      throw new Error(result.error || 'تعذر إرسال النسخة الاحتياطية.');
    }
    alert(`تم إرسال النسخة الاحتياطية بنجاح إلى ${recipient}.`);
  } catch (err) {
    console.error(err);
    alert(err.message || 'تعذر إرسال النسخة الاحتياطية. تحقق من إعداد Gmail واتصال الإنترنت.');
  }
}

function importDataBackup(event) {
  const file = event.target.files[0];
  if (!file) return;

  requirePermission('backups.delete', () => {
    const reader = new FileReader();
    reader.onload = async function(e) {
      try {
        const imported = JSON.parse(e.target.result);
        const importedData = imported.format === 'asia-center-backup' ? imported.data : imported;
        if (importedData?.courses && importedData?.workspace) {
          if (!importedData.dailyPayments) importedData.dailyPayments = [];
          if (!importedData.expenses) importedData.expenses = [];
          if (!importedData.owners) importedData.owners = [];
          if (!importedData.closings) importedData.closings = [];
          if (!importedData.allocations) importedData.allocations = [];
          if (!importedData.rooms) importedData.rooms = [];
          if (!importedData.roomColors) importedData.roomColors = {};
          if (!confirm('سيتم استبدال جميع بيانات النظام. النسخة الكاملة ستستبدل أيضًا حسابات المستخدمين والأدوار، وستحتاج إلى تسجيل الدخول مجددًا ببيانات الحسابات الموجودة في النسخة. هل تريد المتابعة؟')) return;
          const response = await fetch('/api/data/restore', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(imported)
          });
          const result = await response.json();
          if (!response.ok) throw new Error(result.error || 'تعذر استعادة النسخة الاحتياطية.');
          alert('تم استرجاع النسخة الاحتياطية بنجاح. سجّل الدخول مجددًا باستخدام بيانات الحسابات الموجودة في النسخة.');
          location.reload();
        } else {
          alert('الملف المختار غير صالح');
        }
      } catch(err) {
        alert('حدث خطأ أثناء قراءة الملف: ' + err.message);
      }
    };
    reader.readAsText(file);
  });
  event.target.value = '';
}


// ================= EDIT STUDENT & PRINT SHEET LOGIC =================
function openEditStudentModalWithLock(sIdx) {
  requirePermission('students.manage', () => {
    const course = db.courses[currentCourseIndex];
    const s = course.students[sIdx];
    document.getElementById('edit-stu-idx').value = sIdx;
    document.getElementById('edit-stu-name').value = s.name;
    document.getElementById('edit-stu-phone').value = s.phone || '';
    document.getElementById('edit-stu-fee').value = s.fee || course.fee || 2200;
    document.getElementById('modal-edit-student').classList.add('open');
  });
}

function saveEditedStudent() {
  if (!hasPermission('students.manage')) return;
  const sIdx = document.getElementById('edit-stu-idx').value;
  const name = document.getElementById('edit-stu-name').value.trim();
  const phone = document.getElementById('edit-stu-phone').value.trim();
  const fee = Number(document.getElementById('edit-stu-fee').value);

  if (!name || !Number.isFinite(fee) || fee <= 0) {
    alert('يرجى إدخال اسم الطالب وسعر صحيح أكبر من صفر');
    return;
  }

  const course = db.courses[currentCourseIndex];
  const s = course.students[sIdx];
  const oldName = s.name;
  if ((oldName !== name || s.phone !== phone) &&
      db.dailyPayments.some(payment => payment.courseName === course.name && payment.studentName === oldName) &&
      !hasPermission('payments.manage')) return;

  s.name = name;
  s.phone = phone;
  s.fee = fee;
  db.dailyPayments.forEach(payment => {
    if (payment.courseName === course.name && payment.studentName === oldName) {
      payment.studentName = name;
      payment.phone = phone;
    }
  });

  // Also update phone/name in other courses for this student if user wishes to keep unified
  if (phone) {
    db.courses.forEach(c => {
      c.students.forEach(otherS => {
        if (otherS.name.trim() === oldName.trim() && (!otherS.phone || otherS.phone === '')) {
          otherS.phone = phone;
        }
      });
    });
  }

  saveDB();
  closeModal('modal-edit-student');
  renderCourseStudents(currentCourseIndex);
  renderStudentsDirectory();
  renderCoursesTable();
  renderProfessorsTable();
  loadDailyReport();
  alert('تم تحديث بيانات الطالب ورقم الهاتف بنجاح!');
}

function openPrintCourseSheet() {
  if (currentCourseIndex === null) return;
  const course = db.courses[currentCourseIndex];
  document.getElementById('print-sheet-title').innerText = 'كشف حساب مادة: ' + course.name;
  
  const now = new Date();
  document.getElementById('print-sheet-date').innerText = now.toLocaleDateString('ar-EG', { year: 'numeric', month: 'long', day: 'numeric' });
  document.getElementById('print-sheet-count').innerText = course.students.length;

  let totalFee = 0;
  let totalPaid = 0;
  let totalRem = 0;
  let completedCount = 0;

  const tbody = document.getElementById('print-sheet-tbody');
  tbody.innerHTML = course.students.map((s, idx) => {
    const fee = s.fee || course.fee || 2200;
    const paid = s.paid || 0;
    const rem = fee - paid;
    totalFee += fee;
    totalPaid += paid;
    totalRem += rem;

    const isDone = rem <= 0;
    if (isDone) completedCount++;

    return `
      <tr>
        <td style="padding: 7px; border: 1px solid #cbd5e1; text-align: center;">${idx + 1}</td>
        <td style="padding: 7px; border: 1px solid #cbd5e1; font-weight: bold;">${s.name}</td>
        <td style="padding: 7px; border: 1px solid #cbd5e1; direction: ltr; text-align: right;">${s.phone || '<span style="color:#94a3b8;">-</span>'}</td>
        <td style="padding: 7px; border: 1px solid #cbd5e1;">${fee} ج.م</td>
        <td style="padding: 7px; border: 1px solid #cbd5e1; color: #16a34a; font-weight: bold;">${paid} ج.م</td>
        <td style="padding: 7px; border: 1px solid #cbd5e1; color: ${rem > 0 ? '#dc2626' : '#16a34a'}; font-weight: bold;">${rem} ج.م</td>
        <td style="padding: 7px; border: 1px solid #cbd5e1; text-align: center;">
          ${isDone ? '<span style="color: #16a34a; font-weight: bold;">خالص ✔</span>' : `<span style="color: #dc2626; font-weight: bold;">باقي ${rem}</span>`}
        </td>
      </tr>
    `;
  }).join('');

  document.getElementById('print-total-fee').innerText = totalFee.toLocaleString() + ' ج.م';
  document.getElementById('print-total-paid').innerText = totalPaid.toLocaleString() + ' ج.م';
  document.getElementById('print-total-rem').innerText = totalRem.toLocaleString() + ' ج.م';
  document.getElementById('print-total-status').innerText = `${completedCount} من ${course.students.length} خالص`;

  document.getElementById('modal-print-course').classList.add('open');
}

function shareCourseSheetWhatsApp() {
  if (currentCourseIndex === null) return;
  const course = db.courses[currentCourseIndex];
  
  let text = `📋 *كشف حساب مادة: ${course.name}*\n`;
  text += `🏛️ *سنتر آسيا - ASIA CENTER*\n`;
  text += `📅 التاريخ: ${new Date().toLocaleDateString('ar-EG')}\n`;
  text += `👥 عدد الطلاب: ${course.students.length}\n`;
  text += `------------------------------------\n`;

  let totalPaid = 0;
  let totalRem = 0;

  course.students.forEach((s, idx) => {
    const fee = s.fee || course.fee || 2200;
    const paid = s.paid || 0;
    const rem = fee - paid;
    totalPaid += paid;
    totalRem += rem;

    text += `${idx + 1}. *${s.name}*\n`;
    text += `   📱 موبايل: ${s.phone || 'غير مسجل'}\n`;
    text += `   💰 دفع: ${paid} ج.م | باقي: ${rem} ج.م | الحالة: ${rem <= 0 ? 'خالص ✔' : 'متبقي عليه ❌'}\n`;
  });

  text += `------------------------------------\n`;
  text += `💵 *إجمالي المحصل:* ${totalPaid.toLocaleString()} ج.م\n`;
  text += `⏳ *إجمالي المتبقي:* ${totalRem.toLocaleString()} ج.م\n`;

  const url = `https://api.whatsapp.com/send?text=${encodeURIComponent(text)}`;
  window.open(url, '_blank');
}

// Start app
async function startAuthenticatedApp() {
  try {
    if (await initDB() && currentPermissions.has('data.view')) setTodayDate();
  } catch (e) {
    console.error(e);
    alert('تعذر تحميل البيانات. شغّل الملف start.bat ثم افتح الصفحة من المتصفح.');
  }
}

window.onload = startAuthenticatedApp;

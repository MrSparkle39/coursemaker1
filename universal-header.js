/**
 * Universal Header Component for CourseMaker
 * Provides consistent navigation across all pages
 */

class UniversalHeader {
  constructor() {
    this.currentPage = this.getCurrentPage();
    this.isLoggedIn = this.checkAuthStatus();
    this.init();
  }

  getCurrentPage() {
    const path = window.location.pathname;
    const filename = path.split('/').pop() || 'index.html';
    return filename.replace('.html', '');
  }

  checkAuthStatus() {
    // Check if user is logged in by looking for auth indicators
    return document.cookie.includes('auth_token') || 
           localStorage.getItem('user') !== null ||
           this.currentPage === 'dashboard' ||
           this.currentPage === 'courses' ||
           this.currentPage === 'account' ||
           this.currentPage === 'usage' ||
           this.currentPage === 'upgrade' ||
           this.currentPage === 'onboarding' ||
           this.currentPage === 'checkout';
  }

  getNavigationItems() {
    if (this.isLoggedIn) {
      return [
        { href: '/dashboard.html', label: 'Dashboard', active: this.currentPage === 'dashboard' },
        { href: '/courses.html', label: 'My Courses', active: this.currentPage === 'courses' },
        { href: '/usage.html', label: 'Usage', active: this.currentPage === 'usage' },
        { href: '/account.html', label: 'Account', active: this.currentPage === 'account' }
      ];
    } else {
      return [
        { href: '/index.html', label: 'Home', active: this.currentPage === 'index' },
        { href: '/plans.html', label: 'Plans', active: this.currentPage === 'plans' },
        { href: '/index.html#features', label: 'Features', active: false },
        { href: '/index.html#contact', label: 'Contact', active: false }
      ];
    }
  }

  getAuthButtons() {
    if (this.isLoggedIn) {
      return `
        <div class="hidden md:flex items-center gap-2">
          <span class="badge" id="userPlan">Pro Plan</span>
          <span class="text-sm text-slate-400" id="userEmail">user@example.com</span>
        </div>
        <button id="btnLogout" class="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm hover:bg-white/10">Sign out</button>
      `;
    } else {
      return `
        <a href="/login.html" class="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm hover:bg-white/10">Sign In</a>
        <a href="/register.html" class="rounded-xl bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-900 hover:bg-cyan-400">Get Started</a>
      `;
    }
  }

  init() {
    // Insert the header HTML
    const headerHTML = `
      <header class="sticky top-0 z-40 border-b border-white/5 glass">
        <nav class="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 md:px-6">
          <div class="flex items-center gap-3">
            <div class="h-9 w-9 rounded-2xl bg-cyan-500/20 grid place-items-center ring-1 ring-cyan-400/40">✨</div>
            <span class="text-xl font-semibold tracking-tight">CourseMaker</span>
          </div>
          <div class="hidden md:flex items-center gap-8 text-sm text-slate-300" id="navLinks">
            <!-- Navigation links will be populated by JavaScript -->
          </div>
          <div class="flex items-center gap-3" id="authButtons">
            <!-- Auth buttons will be populated by JavaScript -->
          </div>
        </nav>
      </header>
    `;

    // Insert at the beginning of body
    document.body.insertAdjacentHTML('afterbegin', headerHTML);

    // Populate navigation and auth buttons
    this.populateNavigation();
    this.populateAuthButtons();

    // Add event listeners
    this.addEventListeners();
  }

  populateNavigation() {
    const navContainer = document.getElementById('navLinks');
    if (!navContainer) return;

    const navItems = this.getNavigationItems();
    navContainer.innerHTML = navItems.map(item => `
      <a class="hover:text-white ${item.active ? 'font-medium text-cyan-300' : ''}" href="${item.href}">${item.label}</a>
    `).join('');
  }

  populateAuthButtons() {
    const authContainer = document.getElementById('authButtons');
    if (!authContainer) return;

    authContainer.innerHTML = this.getAuthButtons();
  }

  addEventListeners() {
    // Logout functionality
    const logoutBtn = document.getElementById('btnLogout');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', this.handleLogout.bind(this));
    }

    // Update user info if logged in
    if (this.isLoggedIn) {
      this.updateUserInfo();
    }
  }

  async updateUserInfo() {
    try {
      const response = await fetch('/api/user/profile', {
        credentials: 'include'
      });
      
      if (response.ok) {
        const user = await response.json();
        const userEmail = document.getElementById('userEmail');
        const userPlan = document.getElementById('userPlan');
        
        if (userEmail) userEmail.textContent = user.email || 'user@example.com';
        if (userPlan) {
          userPlan.textContent = user.planType ? 
            user.planType.charAt(0).toUpperCase() + user.planType.slice(1) + ' Plan' : 
            'Pro Plan';
          
          // Update plan badge color
          if (user.planType === 'pro') {
            userPlan.className = 'badge text-cyan-300 border-cyan-400/40 bg-cyan-500/20';
          } else if (user.planType === 'business') {
            userPlan.className = 'badge text-purple-300 border-purple-400/40 bg-purple-500/20';
          } else {
            userPlan.className = 'badge text-slate-300 border-slate-400/40 bg-slate-500/20';
          }
        }
      }
    } catch (error) {
      console.error('Error loading user info:', error);
    }
  }

  async handleLogout() {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include'
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      window.location.href = '/login.html';
    }
  }
}

// Initialize the universal header when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new UniversalHeader();
});
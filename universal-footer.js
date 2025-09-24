// Universal Footer Script
// This script automatically inserts the footer on all pages

document.addEventListener('DOMContentLoaded', function() {
  loadFooter();
});

async function loadFooter() {
  try {
    // Check if this is an interactive page or course builder that should not have the footer
    const currentPage = window.location.pathname;
    const excludedPages = [
      'course-builder.html',
      'drag-drop-builder.html',
      'hotspot-builder.html',
      'quiz-builder.html',
      'slide-maker.html'
    ];
    
    const isExcludedPage = excludedPages.some(page => currentPage.includes(page));
    if (isExcludedPage) {
      console.log('Footer excluded for interactive page:', currentPage);
      return;
    }
    
    // Fetch the footer content
    const response = await fetch('footer.html');
    if (!response.ok) {
      console.warn('Could not load footer.html');
      return;
    }
    
    const footerHTML = await response.text();
    
    // Insert footer before closing body tag
    const body = document.body;
    if (body) {
      body.insertAdjacentHTML('beforeend', footerHTML);
      
      // Initialize footer year after insertion
      const yearElement = document.getElementById('yr');
      if (yearElement) {
        yearElement.textContent = new Date().getFullYear();
      }
      
      // Add newsletter functionality
      initializeNewsletter();
    }
  } catch (error) {
    console.warn('Error loading footer:', error);
  }
}

function initializeNewsletter() {
  const emailInput = document.querySelector('input[type="email"]');
  const subscribeButton = document.querySelector('button');
  
  if (emailInput && subscribeButton && subscribeButton.textContent.includes('Subscribe')) {
    subscribeButton.addEventListener('click', function() {
      const email = emailInput.value.trim();
      if (email && isValidEmail(email)) {
        // Here you would typically send the email to your backend
        alert('Thank you for subscribing! We\'ll keep you updated on CourseMaker news and tips.');
        emailInput.value = '';
      } else {
        alert('Please enter a valid email address.');
      }
    });
    
    // Allow Enter key to submit
    emailInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        subscribeButton.click();
      }
    });
  }
}

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Helper function to check if element contains text (for button selector)
function containsText(selector, text) {
  const elements = document.querySelectorAll(selector);
  for (let element of elements) {
    if (element.textContent.includes(text)) {
      return element;
    }
  }
  return null;
}
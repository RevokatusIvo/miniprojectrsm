document.addEventListener('DOMContentLoaded', function() {
    // Load sidebar
    loadSidebar();
    
    // Set active menu based on current page
    setActiveMenu();
});

async function loadSidebar() {
    try {
        const response = await fetch('/static/sidebar.html');
        const data = await response.text();
        document.querySelector('.wrapper').insertAdjacentHTML('afterbegin', data);
    } catch (error) {
        console.error('Error loading sidebar:', error);
    }
}

function setActiveMenu() {
    const currentPage = window.location.pathname.split('/').pop() || 'dashboard.html';
    const navLinks = document.querySelectorAll('.nav-links li');
    
    navLinks.forEach(link => {
        const anchor = link.querySelector('a');
        if (anchor.getAttribute('href') === currentPage) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });
}

// Toggle sidebar for mobile
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const mainContent = document.querySelector('.main-content');
    
    sidebar.classList.toggle('collapsed');
    mainContent.classList.toggle('expanded');
}

// Add resize listener to handle responsive behavior
window.addEventListener('resize', function() {
    const sidebar = document.querySelector('.sidebar');
    if (window.innerWidth <= 768) {
        sidebar.classList.add('collapsed');
    } else {
        sidebar.classList.remove('collapsed');
    }
});


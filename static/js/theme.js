// static/js/theme.js

// 1. Initialisation immédiate pour éviter le clignotement
(function initTheme() {
    const savedTheme = localStorage.getItem('theme');
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    const themeToApply = savedTheme || (systemPrefersDark ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', themeToApply);
})();

// 2. Fonction de basculement appelée par le bouton
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    updateThemeIcon(newTheme);
}

// 3. Mise à jour de l'icône du bouton
function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (!icon) return;
    
    if (theme === 'dark') {
        icon.className = 'ri-sun-line'; // Icône soleil RemixIcon
    } else {
        icon.className = 'ri-moon-line'; // Icône lune RemixIcon
    }
}

// Au chargement du DOM, synchroniser l'icône
document.addEventListener('DOMContentLoaded', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    updateThemeIcon(currentTheme);
});
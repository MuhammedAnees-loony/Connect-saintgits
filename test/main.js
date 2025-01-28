document.addEventListener('DOMContentLoaded', () => {
    const menuBtn = document.querySelector('.menu-btn');
    const mainNav = document.querySelector('.main-nav');
    const scrollTopBtn = document.querySelector('.scroll-top');

    menuBtn?.addEventListener('click', () => {
        const isExpanded = menuBtn.getAttribute('aria-expanded') === 'true';
        menuBtn.setAttribute('aria-expanded', !isExpanded);
        mainNav?.classList.toggle('is-active');
    });

    scrollTopBtn?.addEventListener('click', () => {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });

    const handleScroll = () => {
        if (scrollTopBtn) {
            scrollTopBtn.style.display = window.scrollY > 200 ? 'flex' : 'none';
        }
    };

    window.addEventListener('scroll', handleScroll);
    handleScroll();
});
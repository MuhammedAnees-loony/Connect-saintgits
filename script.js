gsap.fromTo(
    ".loading-page",
    { opacity: 1 },
    {
      opacity: 0,
      display: "none",
      duration: 1.5,
      delay: 3.5,
    }
  );
  
  gsap.fromTo(
    ".logo-name",
    {
      y: 50,
      opacity: 0,
    },
    {
      y: 0,
      opacity: 1,
      duration: 2,
      delay: 0.5,
    }
  );
  document.addEventListener("DOMContentLoaded", () => {
    setTimeout(() => {
        const loadingPage = document.querySelector(".loading-page");
        loadingPage.style.transition = "opacity 1.5s ease-out"; // Smooth fade-out
        loadingPage.style.opacity = "0"; 

        setTimeout(() => {
            window.location.href = "home.html"; // Redirect after fade-out
        }, 0); // Wait for fade-out effect
    }, 4000); // Adjust time to match animation duration
});


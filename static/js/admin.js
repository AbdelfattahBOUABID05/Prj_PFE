// Admin users page safety helpers:
// - Ensure modal triggers never submit forms accidentally
// - Provide minimal console diagnostics instead of freezing UI

document.addEventListener('DOMContentLoaded', () => {
    // Ensure any modal trigger buttons are type="button"
    document.querySelectorAll('button[data-bs-toggle="modal"]').forEach((btn) => {
        if (!btn.getAttribute('type')) btn.setAttribute('type', 'button');
    });

    // Trap common issues: missing bootstrap JS or broken modal targets
    document.querySelectorAll('button[data-bs-toggle="modal"][data-bs-target]').forEach((btn) => {
        const sel = btn.getAttribute('data-bs-target');
        if (!sel) return;
        const modal = document.querySelector(sel);
        if (!modal) {
            // eslint-disable-next-line no-console
            console.error(`[admin] Missing modal target: ${sel}`);
        }
    });
});


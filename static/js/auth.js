function attachBootstrapValidation(form) {
    if (!form) return;
    form.addEventListener('submit', (e) => {
        if (!form.checkValidity()) {
            e.preventDefault();
            e.stopPropagation();
        }
        form.classList.add('was-validated');
    });
}

function attachPasswordMatch(form) {
    if (!form) return;
    const pw = form.querySelector('#regPassword');
    const cpw = form.querySelector('#confirmPassword');
    const confirmFeedback = form.querySelector('#confirmFeedback');
    if (!pw || !cpw) return;

    function validateMatch() {
        const ok = pw.value && cpw.value && pw.value === cpw.value;
        if (!cpw.value) {
            cpw.setCustomValidity('');
            if (confirmFeedback) confirmFeedback.textContent = 'Les mots de passe doivent correspondre.';
            return;
        }
        cpw.setCustomValidity(ok ? '' : 'mismatch');
        if (confirmFeedback) confirmFeedback.textContent = ok ? '' : 'Les mots de passe doivent correspondre.';
    }

    pw.addEventListener('input', validateMatch);
    cpw.addEventListener('input', validateMatch);
    form.addEventListener('submit', validateMatch);
}

document.addEventListener('DOMContentLoaded', () => {
    attachBootstrapValidation(document.getElementById('loginForm'));

    const registerForm = document.getElementById('registerForm');
    attachBootstrapValidation(registerForm);
    attachPasswordMatch(registerForm);
});


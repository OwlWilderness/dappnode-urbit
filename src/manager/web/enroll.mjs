const form = document.getElementById('enroll-form');
const message = document.getElementById('message');
const submit = document.getElementById('enroll');
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (submit.disabled) return;
  const authorityField = document.getElementById('authority');
  const passwordField = document.getElementById('password');
  const authority = authorityField.value;
  const password = passwordField.value;
  authorityField.value = '';
  passwordField.value = '';
  submit.disabled = true;
  try {
    const response = await fetch('/api/enroll', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authority, password })
    });
    if (!response.ok) throw new Error('refused');
    message.textContent = 'Enrollment recorded. Reload this page, then sign in with your importer password. No ship was started.';
  } catch {
    message.textContent = 'Enrollment refused or unavailable. Check the private route and configuration; do not retry a lost acknowledgement without checking the locked state.';
  }
});

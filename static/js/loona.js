/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Целиков Евгений */

// Page behaviour kept out of the HTML, so the Content-Security-Policy can
// refuse inline script.
// <form data-confirm="Delete it?">: ask first.
// <select data-autosubmit>: send the form when the choice changes.
document.addEventListener("submit", (event) => {
  const text = event.target.dataset && event.target.dataset.confirm;
  if (text && !window.confirm(text)) event.preventDefault();
}, true);
document.addEventListener("change", (event) => {
  const field = event.target;
  if (field.matches && field.matches("[data-autosubmit]") && field.form) field.form.requestSubmit();
});

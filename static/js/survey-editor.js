/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Целиков Евгений */

// The survey editor on a launch template's page: questions as a list,
// written back as JSON into the form's hidden "survey" field. The server
// checks everything again (runs.surveys.clean_spec).
document.addEventListener("alpine:init", () => {
  window.Alpine.data("surveyEditor", (source) => ({
    questions: [],
    init() {
      const raw = JSON.parse(document.getElementById(source).textContent || "[]");
      this.questions = raw.map((q) => ({
        variable: q.variable || "", label: q.label || "", help: q.help || "",
        type: q.type || "text", required: !!q.required,
        choices: Array.isArray(q.choices) ? q.choices.join("\n") : (q.choices || ""),
        default: Array.isArray(q.default) ? q.default.join("\n") : (q.default ?? ""),
        min: q.min ?? "", max: q.max ?? "",
      }));
    },
    add() {
      this.questions.push({ variable: "", label: "", help: "", type: "text", required: false,
                            choices: "", default: "", min: "", max: "" });
    },
    remove(i) { this.questions.splice(i, 1); },
    move(i, step) {
      const j = i + step;
      if (j < 0 || j >= this.questions.length) return;
      const [q] = this.questions.splice(i, 1);
      this.questions.splice(j, 0, q);
    },
    hasChoices(q) { return q.type === "choice" || q.type === "multichoice"; },
    isNumber(q) { return q.type === "integer" || q.type === "float"; },
    get json() {
      return JSON.stringify(this.questions.map((q) => {
        const out = { variable: q.variable.trim(), label: q.label.trim(), help: q.help.trim(),
                      type: q.type, required: q.required };
        if (this.hasChoices(q)) out.choices = q.choices.split("\n").map((c) => c.trim()).filter(Boolean);
        if (this.isNumber(q)) { out.min = q.min; out.max = q.max; }
        if (q.type === "multichoice") out.default = String(q.default).split("\n").map((c) => c.trim()).filter(Boolean);
        else if (q.type === "boolean") out.default = q.default === true || q.default === "true";
        else if (q.type !== "password") out.default = q.default;
        return out;
      }));
    },
  }));
});

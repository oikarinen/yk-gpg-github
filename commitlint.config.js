module.exports = {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "scope-empty": [2, "never"],
    "scope-enum": [
      2,
      "always",
      [
        "deps",
        "deps-dev",
        "root",
        "github-actions",
      ],
    ],
    "footer-max-line-length": [0],
    "body-max-line-length": [0],
  },
};

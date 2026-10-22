export function renderUserInput(html) {
  // Intentional DOM XSS via innerHTML
  document.getElementById('out').innerHTML = html;
}

export function executeExpr(input) {
  // Intentional eval() RCE in JS
  return eval(input);
}

export function runCmd(userInput) {
  // Intentional command injection via child_process.exec
  const { exec } = require('child_process');
  exec(`echo ${userInput}`, () => {});
}

export function createFn(code) {
  // Intentional new Function() (eval-equivalent)
  return new Function(code);
}

// Intentional hardcoded GitHub token in source
const GITHUB_TOKEN = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';

// Intentional hygiene issues
console.log('app booted');
debugger;

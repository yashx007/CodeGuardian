// JS test file with eval, child_process exec and SQL template usage
const { exec } = require('child_process');

const secret = "MY_JS_API_KEY_1234567890";

// eval usage
const s = "1 + 1";
eval(s);

// child_process exec
exec('ls -la', (err, stdout, stderr) => {
  // noop
});

// SQL-like concatenation
const name = "admin";
const query = "SELECT * FROM users WHERE name = '" + name + "'";

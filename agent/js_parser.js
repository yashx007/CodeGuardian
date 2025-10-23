// Lightweight JS AST scanner using esprima (if installed)
// Usage: node js_parser.js /path/to/file.js

const fs = require('fs');
let esprima;
try {
  esprima = require('esprima');
} catch (e) {
  console.error('esprima not available');
  process.exit(2);
}

const path = process.argv[2];
if (!path) {
  console.error('Usage: node js_parser.js <file.js>');
  process.exit(2);
}

const src = fs.readFileSync(path, 'utf8');
let ast;
try {
  ast = esprima.parseModule(src, { tolerant: true, loc: true, range: true });
} catch (e) {
  console.error('parse error', e.message);
  process.exit(2);
}

const issues = [];
const childProcessBindings = new Set();

function walk(node, parent) {
  if (!node) return;
  switch (node.type) {
    case 'CallExpression':
      if (node.callee && node.callee.type === 'Identifier' && node.callee.name === 'eval') {
        issues.push({ type: 'Insecure Function Usage', line: node.loc.start.line, snippet: src.split('\n')[node.loc.start.line-1].trim(), message: 'Use of eval() in JS can lead to code injection.' });
      }
      // child_process.exec or require('child_process').exec or destructured binding 'exec'
      if (node.callee) {
        if (node.callee.type === 'MemberExpression') {
          let obj = node.callee.object;
          let prop = node.callee.property;
          if (obj && prop && ((obj.type === 'Identifier' && obj.name === 'child_process') || (obj.type === 'CallExpression' && obj.callee.name === 'require'))) {
            if (prop.type === 'Identifier' && prop.name === 'exec') {
              issues.push({ type: 'Suspicious Subprocess Call', line: node.loc.start.line, snippet: src.split('\n')[node.loc.start.line-1].trim(), message: 'child_process.exec detected.' });
            }
          }
        } else if (node.callee.type === 'Identifier') {
          // call to exec(...) where exec was bound via require destructuring
          if (childProcessBindings.has(node.callee.name)) {
            issues.push({ type: 'Suspicious Subprocess Call', line: node.loc.start.line, snippet: src.split('\n')[node.loc.start.line-1].trim(), message: 'child_process.exec (via destructured binding) detected.' });
          }
        }
      }
      break;
    case 'NewExpression':
      if (node.callee && node.callee.name === 'RegExp') {
        // try to find pattern arg
        if (node.arguments && node.arguments[0] && node.arguments[0].type === 'Literal' && typeof node.arguments[0].value === 'string') {
          const pat = node.arguments[0].value;
          if (pat.includes('.*')) {
            issues.push({ type: 'Insecure Regex', line: node.loc.start.line, snippet: src.split('\n')[node.loc.start.line-1].trim(), message: 'RegExp with .* detected.' });
          }
        }
      }
      break;
    case 'TemplateLiteral':
      // check for SQL keywords in cooked strings
      for (const q of node.quasis) {
        if (/(select|insert|update|delete|where|from)/i.test(q.value.cooked)) {
          issues.push({ type: 'Possible SQL Injection', line: node.loc.start.line, snippet: src.split('\n')[node.loc.start.line-1].trim(), message: 'Template literal contains SQL keyword; check for parameterization.' });
        }
      }
      break;
  }

  for (const key of Object.keys(node)) {
    const child = node[key];
    if (Array.isArray(child)) {
      child.forEach(c => { if (c && typeof c.type === 'string') walk(c, node); });
    } else if (child && typeof child.type === 'string') {
      walk(child, node);
    }
  }
}

// Second pass: collect destructured require bindings
function collectBindings(node){
  if(!node) return;
  if(node.type === 'VariableDeclaration'){
    for(const decl of node.declarations){
      if(decl.id && decl.id.type === 'ObjectPattern' && decl.init && decl.init.type === 'CallExpression' && decl.init.callee && decl.init.callee.name === 'require'){
        if(decl.init.arguments && decl.init.arguments[0] && decl.init.arguments[0].value === 'child_process'){
          // collect properties
          for(const prop of decl.id.properties){
            if(prop.key && prop.key.name){
              childProcessBindings.add(prop.key.name);
            }
          }
        }
      }
    }
  }
  for (const key of Object.keys(node)){
    const child = node[key];
    if(Array.isArray(child)) child.forEach(c=>{ if(c && typeof c.type === 'string') collectBindings(c); });
    else if(child && typeof child.type === 'string') collectBindings(child);
  }
}

collectBindings(ast);

walk(ast, null);
console.log(JSON.stringify(issues));

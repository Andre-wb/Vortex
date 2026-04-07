/* ============================================================
   IDE Dev Settings — themes, editor features, unique extras
   ============================================================ */
'use strict';

/* ── 55 editor themes ─────────────────────────────────────── */
const IDE_THEMES = [
  /* id, label, dark?, bg, gutter, text, kw, type, str, comment, num, regex, arrow, ctx, interp, sel, cursor, preview[3] */
  { id:'vortex-night',       label:'Vortex Night',       dark:true,  bg:'#0d0d18', gutter:'#0b0b14', text:'#e2e8f0', kw:'#c084fc', type:'#67e8f9', str:'#86efac', comment:'#475569', num:'#fde68a', regex:'#fda4af', arrow:'#a78bfa', ctx:'#38bdf8', interp:'#fb923c', sel:'rgba(167,139,250,.22)', cursor:'#c084fc',  preview:['#0d0d18','#c084fc','#86efac'] },
  { id:'dracula',            label:'Dracula',            dark:true,  bg:'#282a36', gutter:'#21222c', text:'#f8f8f2', kw:'#ff79c6', type:'#8be9fd', str:'#f1fa8c', comment:'#6272a4', num:'#bd93f9', regex:'#ff5555', arrow:'#ff79c6', ctx:'#50fa7b', interp:'#ffb86c', sel:'rgba(98,114,164,.4)',  cursor:'#f8f8f0',  preview:['#282a36','#ff79c6','#f1fa8c'] },
  { id:'monokai',            label:'Monokai',            dark:true,  bg:'#272822', gutter:'#1e1f1c', text:'#f8f8f2', kw:'#f92672', type:'#66d9e8', str:'#e6db74', comment:'#75715e', num:'#ae81ff', regex:'#f92672', arrow:'#f92672', ctx:'#a6e22e', interp:'#fd971f', sel:'rgba(73,72,62,.6)',   cursor:'#f8f8f0',  preview:['#272822','#f92672','#e6db74'] },
  { id:'one-dark',           label:'One Dark',           dark:true,  bg:'#282c34', gutter:'#21252b', text:'#abb2bf', kw:'#c678dd', type:'#56b6c2', str:'#98c379', comment:'#5c6370', num:'#d19a66', regex:'#e06c75', arrow:'#56b6c2', ctx:'#61afef', interp:'#e06c75', sel:'rgba(97,175,239,.2)', cursor:'#528bff',  preview:['#282c34','#c678dd','#98c379'] },
  { id:'material-dark',      label:'Material Dark',      dark:true,  bg:'#212121', gutter:'#1a1a1a', text:'#eeffff', kw:'#c792ea', type:'#80cbc4', str:'#c3e88d', comment:'#546e7a', num:'#f78c6c', regex:'#f07178', arrow:'#89ddff', ctx:'#82aaff', interp:'#ff9800', sel:'rgba(130,170,255,.2)',cursor:'#ffcc00',  preview:['#212121','#c792ea','#c3e88d'] },
  { id:'palenight',          label:'Palenight',          dark:true,  bg:'#292d3e', gutter:'#22263a', text:'#a6accd', kw:'#c792ea', type:'#80cbc4', str:'#c3e88d', comment:'#676e95', num:'#f78c6c', regex:'#f07178', arrow:'#89ddff', ctx:'#82aaff', interp:'#ff9800', sel:'rgba(103,110,149,.3)',cursor:'#ffcc00',  preview:['#292d3e','#c792ea','#c3e88d'] },
  { id:'tokyo-night',        label:'Tokyo Night',        dark:true,  bg:'#1a1b26', gutter:'#16161e', text:'#c0caf5', kw:'#bb9af7', type:'#2ac3de', str:'#9ece6a', comment:'#565f89', num:'#ff9e64', regex:'#f7768e', arrow:'#7dcfff', ctx:'#7aa2f7', interp:'#ff9e64', sel:'rgba(41,46,66,.9)',   cursor:'#c0caf5',  preview:['#1a1b26','#bb9af7','#9ece6a'] },
  { id:'gruvbox-dark',       label:'Gruvbox Dark',       dark:true,  bg:'#282828', gutter:'#1d2021', text:'#ebdbb2', kw:'#fb4934', type:'#8ec07c', str:'#b8bb26', comment:'#928374', num:'#d3869b', regex:'#fe8019', arrow:'#d3869b', ctx:'#fabd2f', interp:'#fe8019', sel:'rgba(80,73,69,.6)',   cursor:'#ebdbb2',  preview:['#282828','#fb4934','#b8bb26'] },
  { id:'nord',               label:'Nord',               dark:true,  bg:'#2e3440', gutter:'#252a33', text:'#d8dee9', kw:'#81a1c1', type:'#8fbcbb', str:'#a3be8c', comment:'#4c566a', num:'#b48ead', regex:'#bf616a', arrow:'#88c0d0', ctx:'#5e81ac', interp:'#d08770', sel:'rgba(67,76,94,.6)',   cursor:'#d8dee9',  preview:['#2e3440','#81a1c1','#a3be8c'] },
  { id:'catppuccin-mocha',   label:'Catppuccin Mocha',   dark:true,  bg:'#1e1e2e', gutter:'#181825', text:'#cdd6f4', kw:'#cba6f7', type:'#89dceb', str:'#a6e3a1', comment:'#6c7086', num:'#fab387', regex:'#f38ba8', arrow:'#89b4fa', ctx:'#89dceb', interp:'#fab387', sel:'rgba(88,91,112,.5)',  cursor:'#f5e0dc',  preview:['#1e1e2e','#cba6f7','#a6e3a1'] },
  { id:'catppuccin-macchiato',label:'Catppuccin Macchiato',dark:true,bg:'#24273a', gutter:'#1e2030', text:'#cad3f5', kw:'#c6a0f6', type:'#8bd5ca', str:'#a6da95', comment:'#6e738d', num:'#f5a97f', regex:'#ed8796', arrow:'#8aadf4', ctx:'#7dc4e4', interp:'#f5a97f', sel:'rgba(91,96,120,.5)',  cursor:'#f4dbd6',  preview:['#24273a','#c6a0f6','#a6da95'] },
  { id:'solarized-dark',     label:'Solarized Dark',     dark:true,  bg:'#002b36', gutter:'#073642', text:'#839496', kw:'#859900', type:'#2aa198', str:'#2aa198', comment:'#586e75', num:'#d33682', regex:'#dc322f', arrow:'#268bd2', ctx:'#268bd2', interp:'#cb4b16', sel:'rgba(7,54,66,.8)',    cursor:'#839496',  preview:['#002b36','#859900','#2aa198'] },
  { id:'cobalt',             label:'Cobalt',             dark:true,  bg:'#002240', gutter:'#001b33', text:'#ffffff', kw:'#ff9d00', type:'#80fcff', str:'#3ad900', comment:'#0088ff', num:'#80fcff', regex:'#ff628c', arrow:'#ff9d00', ctx:'#80fcff', interp:'#ccff33', sel:'rgba(0,136,255,.3)',  cursor:'#ffffff',  preview:['#002240','#ff9d00','#3ad900'] },
  { id:'vscode-dark',        label:'VS Code Dark+',      dark:true,  bg:'#1e1e1e', gutter:'#1e1e1e', text:'#d4d4d4', kw:'#569cd6', type:'#4ec9b0', str:'#ce9178', comment:'#6a9955', num:'#b5cea8', regex:'#d16969', arrow:'#4fc1ff', ctx:'#9cdcfe', interp:'#ce9178', sel:'rgba(38,79,120,.6)',  cursor:'#aeafad',  preview:['#1e1e1e','#569cd6','#ce9178'] },
  { id:'synthwave',          label:"Synthwave '84",      dark:true,  bg:'#262335', gutter:'#1e1b2b', text:'#ffffff', kw:'#ff7edb', type:'#36f9f6', str:'#ff8b39', comment:'#848bbd', num:'#f97e72', regex:'#fe4450', arrow:'#ff7edb', ctx:'#36f9f6', interp:'#ff8b39', sel:'rgba(255,126,219,.2)', cursor:'#ff7edb', preview:['#262335','#ff7edb','#36f9f6'] },
  { id:'cyberpunk',          label:'Cyberpunk',          dark:true,  bg:'#120e1f', gutter:'#0d0a18', text:'#fffb00', kw:'#ff2fc8', type:'#01feff', str:'#ff4af0', comment:'#6c5c99', num:'#ffcc00', regex:'#ff2f2f', arrow:'#ff2fc8', ctx:'#01feff', interp:'#ff8000', sel:'rgba(255,47,200,.2)',  cursor:'#fffb00',  preview:['#120e1f','#ff2fc8','#01feff'] },
  { id:'matrix',             label:'Matrix',             dark:true,  bg:'#0a0a0a', gutter:'#050505', text:'#00ff41', kw:'#00bb2d', type:'#00ff41', str:'#008f11', comment:'#005500', num:'#00ff41', regex:'#00ff41', arrow:'#00d400', ctx:'#008f11', interp:'#00ff41', sel:'rgba(0,255,65,.15)',   cursor:'#00ff41',  preview:['#0a0a0a','#00ff41','#00bb2d'] },
  { id:'midnight-blue',      label:'Midnight Blue',      dark:true,  bg:'#10151e', gutter:'#0d1018', text:'#a8b8d8', kw:'#7090e0', type:'#50c8d0', str:'#70d870', comment:'#384858', num:'#d8a858', regex:'#e07070', arrow:'#a898f8', ctx:'#70b8e8', interp:'#e09050', sel:'rgba(112,144,224,.2)', cursor:'#a8b8d8', preview:['#10151e','#7090e0','#70d870'] },
  { id:'deep-ocean',         label:'Deep Ocean',         dark:true,  bg:'#0f111a', gutter:'#090b11', text:'#8f93a2', kw:'#c792ea', type:'#89ddff', str:'#c3e88d', comment:'#464b5d', num:'#f78c6c', regex:'#ff5370', arrow:'#89ddff', ctx:'#82aaff', interp:'#f78c6c', sel:'rgba(130,170,255,.15)',cursor:'#c792ea',  preview:['#0f111a','#c792ea','#c3e88d'] },
  { id:'moonlight',          label:'Moonlight',          dark:true,  bg:'#1d2030', gutter:'#181b26', text:'#c8d3f5', kw:'#ff98a4', type:'#86e1fc', str:'#c3e88d', comment:'#636e8a', num:'#ff966c', regex:'#ff5370', arrow:'#65bcff', ctx:'#65bcff', interp:'#fca7ea', sel:'rgba(99,110,138,.4)',  cursor:'#c8d3f5',  preview:['#1d2030','#ff98a4','#c3e88d'] },
  { id:'obsidian',           label:'Obsidian',           dark:true,  bg:'#1a1a1a', gutter:'#161616', text:'#e0e0e0', kw:'#678cb1', type:'#93c763', str:'#ec7600', comment:'#66747b', num:'#ffcd22', regex:'#d39745', arrow:'#678cb1', ctx:'#93c763', interp:'#ec7600', sel:'rgba(103,140,177,.3)', cursor:'#e0e0e0',  preview:['#1a1a1a','#678cb1','#93c763'] },
  { id:'neon-dreams',        label:'Neon Dreams',        dark:true,  bg:'#09090e', gutter:'#06060a', text:'#e0ddff', kw:'#ff00ff', type:'#00ffff', str:'#00ff88', comment:'#3a3a5c', num:'#ff8800', regex:'#ff0044', arrow:'#aa00ff', ctx:'#00ddff', interp:'#ff6600', sel:'rgba(255,0,255,.15)',   cursor:'#ff00ff',  preview:['#09090e','#ff00ff','#00ff88'] },
  { id:'purple-haze',        label:'Purple Haze',        dark:true,  bg:'#1b1427', gutter:'#150f1e', text:'#d4c4f0', kw:'#e879f9', type:'#a78bfa', str:'#86efac', comment:'#4a3760', num:'#fde68a', regex:'#f87171', arrow:'#c084fc', ctx:'#7c3aed', interp:'#fb923c', sel:'rgba(232,121,249,.18)', cursor:'#e879f9', preview:['#1b1427','#e879f9','#86efac'] },
  { id:'dark-candy',         label:'Dark Candy',         dark:true,  bg:'#1c1c28', gutter:'#161620', text:'#ffe0f0', kw:'#ff6eb4', type:'#64efef', str:'#adf87a', comment:'#555570', num:'#ffcc44', regex:'#ff4466', arrow:'#ee88ff', ctx:'#44ddff', interp:'#ffaa33', sel:'rgba(255,110,180,.18)', cursor:'#ff6eb4', preview:['#1c1c28','#ff6eb4','#adf87a'] },
  { id:'gravity',            label:'Gravity',            dark:true,  bg:'#1c1e28', gutter:'#171920', text:'#c5cee0', kw:'#8eb0c3', type:'#60c0e8', str:'#94c980', comment:'#515d70', num:'#e8c080', regex:'#e07070', arrow:'#8eb0c3', ctx:'#60c0e8', interp:'#e0a060', sel:'rgba(142,176,195,.2)', cursor:'#c5cee0',  preview:['#1c1e28','#8eb0c3','#94c980'] },
  { id:'afterglow',          label:'Afterglow',          dark:true,  bg:'#2f2930', gutter:'#272228', text:'#d0c8c6', kw:'#ac4a4a', type:'#7e9dbf', str:'#7d9b4f', comment:'#765b61', num:'#b86a35', regex:'#ac4a4a', arrow:'#b96460', ctx:'#7e9dbf', interp:'#b86a35', sel:'rgba(172,74,74,.3)',   cursor:'#d0c8c6',  preview:['#2f2930','#ac4a4a','#7d9b4f'] },
  { id:'aurora',             label:'Aurora',             dark:true,  bg:'#0a1628', gutter:'#071020', text:'#c8d4e8', kw:'#4bf0c0', type:'#60c8ff', str:'#9dffa0', comment:'#304060', num:'#ffd060', regex:'#ff6060', arrow:'#40e0c0', ctx:'#60a0f0', interp:'#ff9030', sel:'rgba(75,240,192,.15)',  cursor:'#4bf0c0',  preview:['#0a1628','#4bf0c0','#9dffa0'] },
  { id:'volcano',            label:'Volcano',            dark:true,  bg:'#1a0e08', gutter:'#130a04', text:'#e8c8a0', kw:'#ff6030', type:'#ff9040', str:'#d4c060', comment:'#604030', num:'#ffcc60', regex:'#ff3020', arrow:'#ff8040', ctx:'#e08040', interp:'#ff6020', sel:'rgba(255,96,48,.2)',    cursor:'#ff6030',  preview:['#1a0e08','#ff6030','#d4c060'] },
  { id:'horizon',            label:'Horizon',            dark:true,  bg:'#1c1e26', gutter:'#16181e', text:'#d5d8da', kw:'#e95678', type:'#25b0bc', str:'#09f7a0', comment:'#6c6f93', num:'#fab28b', regex:'#ec6a88', arrow:'#b877db', ctx:'#26bbd9', interp:'#fab28b', sel:'rgba(233,86,120,.2)',   cursor:'#e95678',  preview:['#1c1e26','#e95678','#09f7a0'] },
  { id:'oceanic-next',       label:'Oceanic Next',       dark:true,  bg:'#1b2b34', gutter:'#162129', text:'#cdd3de', kw:'#c594c5', type:'#fac863', str:'#99c794', comment:'#65737e', num:'#f99157', regex:'#ec5f67', arrow:'#5fb3b3', ctx:'#6699cc', interp:'#e77c39', sel:'rgba(101,115,126,.4)',  cursor:'#cdd3de',  preview:['#1b2b34','#c594c5','#99c794'] },
  { id:'night-owl',          label:'Night Owl',          dark:true,  bg:'#011627', gutter:'#01111e', text:'#d6deeb', kw:'#c792ea', type:'#addb67', str:'#ecc48d', comment:'#637777', num:'#f78c6c', regex:'#ff5874', arrow:'#7fdbca', ctx:'#82aaff', interp:'#ff9d00', sel:'rgba(29,59,83,.5)',    cursor:'#80a4c2',  preview:['#011627','#c792ea','#addb67'] },
  { id:'city-lights',        label:'City Lights',        dark:true,  bg:'#1d252c', gutter:'#171f24', text:'#718ca1', kw:'#5ec4ff', type:'#68a1f0', str:'#8bd49c', comment:'#3e5769', num:'#e27e8d', regex:'#e27e8d', arrow:'#5ec4ff', ctx:'#5ec4ff', interp:'#ebbf83', sel:'rgba(94,196,255,.15)',  cursor:'#5ec4ff',  preview:['#1d252c','#5ec4ff','#8bd49c'] },
  { id:'zenburn',            label:'Zenburn',            dark:true,  bg:'#3f3f3f', gutter:'#353535', text:'#dcdccc', kw:'#f0dfaf', type:'#8cd0d3', str:'#cc9393', comment:'#7f9f7f', num:'#8fb28f', regex:'#dc8cc3', arrow:'#dca3a3', ctx:'#93e0e3', interp:'#e3ceab', sel:'rgba(240,223,175,.2)',  cursor:'#8fb28f',  preview:['#3f3f3f','#f0dfaf','#cc9393'] },
  { id:'shades-of-purple',   label:'Shades of Purple',   dark:true,  bg:'#2d2b55', gutter:'#252350', text:'#a599e9', kw:'#ff9d00', type:'#fb94ff', str:'#a5ff90', comment:'#7858a6', num:'#ff628c', regex:'#ff5371', arrow:'#fb94ff', ctx:'#9effff', interp:'#ff9d00', sel:'rgba(97,80,202,.5)',    cursor:'#fb94ff',  preview:['#2d2b55','#ff9d00','#a5ff90'] },
  { id:'iceberg',            label:'Iceberg',            dark:true,  bg:'#161821', gutter:'#11131a', text:'#c6c8d1', kw:'#84a0c6', type:'#89b8c2', str:'#b4be82', comment:'#444b71', num:'#e2a478', regex:'#e27878', arrow:'#ada0d3', ctx:'#89b8c2', interp:'#e2aa55', sel:'rgba(132,160,198,.25)', cursor:'#c6c8d1',  preview:['#161821','#84a0c6','#b4be82'] },
  { id:'polaris',            label:'Polaris',            dark:true,  bg:'#1a2538', gutter:'#15202e', text:'#c8d4e8', kw:'#4ad0d0', type:'#70b0ff', str:'#88e880', comment:'#3a5060', num:'#f8d060', regex:'#e06060', arrow:'#40c8e0', ctx:'#6090e0', interp:'#f08040', sel:'rgba(74,208,208,.18)',   cursor:'#4ad0d0',  preview:['#1a2538','#4ad0d0','#88e880'] },
  { id:'plasma',             label:'Plasma',             dark:true,  bg:'#0e0b1a', gutter:'#090713', text:'#d4c9f0', kw:'#c95cff', type:'#5cd8f0', str:'#80f0a0', comment:'#4a3870', num:'#ffd080', regex:'#ff5070', arrow:'#b080ff', ctx:'#60c8f0', interp:'#ff8840', sel:'rgba(201,92,255,.18)',   cursor:'#c95cff',  preview:['#0e0b1a','#c95cff','#80f0a0'] },
  { id:'firewatch',          label:'Firewatch',          dark:true,  bg:'#241c1c', gutter:'#1d1515', text:'#e8d8c4', kw:'#e84545', type:'#f9a440', str:'#c8e060', comment:'#7a5045', num:'#f9c460', regex:'#e84545', arrow:'#f08030', ctx:'#f9a440', interp:'#e86020', sel:'rgba(232,69,69,.2)',    cursor:'#e84545',  preview:['#241c1c','#e84545','#c8e060'] },
  { id:'vesper',             label:'Vesper',             dark:true,  bg:'#101010', gutter:'#0c0c0c', text:'#ffffff', kw:'#ffc799', type:'#f38ba8', str:'#b9f27c', comment:'#606060', num:'#d7a2a2', regex:'#f38ba8', arrow:'#ffc799', ctx:'#79b4f0', interp:'#ffc799', sel:'rgba(255,199,153,.18)',  cursor:'#ffc799',  preview:['#101010','#ffc799','#b9f27c'] },
  { id:'tomorrow-night',     label:'Tomorrow Night',     dark:true,  bg:'#1d1f21', gutter:'#171919', text:'#c5c8c6', kw:'#b294bb', type:'#81a2be', str:'#b5bd68', comment:'#969896', num:'#de935f', regex:'#cc6666', arrow:'#81a2be', ctx:'#8abeb7', interp:'#de935f', sel:'rgba(178,148,187,.25)', cursor:'#c5c8c6',  preview:['#1d1f21','#b294bb','#b5bd68'] },
  { id:'base16-ocean',       label:'Base16 Ocean',       dark:true,  bg:'#2b303b', gutter:'#232830', text:'#c0c5ce', kw:'#b48ead', type:'#96b5b4', str:'#a3be8c', comment:'#65737e', num:'#d08770', regex:'#bf616a', arrow:'#8fa1b3', ctx:'#ebcb8b', interp:'#d08770', sel:'rgba(143,161,179,.3)',  cursor:'#c0c5ce',  preview:['#2b303b','#b48ead','#a3be8c'] },
  { id:'seti',               label:'Seti',               dark:true,  bg:'#151718', gutter:'#111313', text:'#cfd2d1', kw:'#cd3f45', type:'#7494a3', str:'#55b5db', comment:'#41535b', num:'#9fca56', regex:'#cd3f45', arrow:'#7494a3', ctx:'#55b5db', interp:'#e6cd69', sel:'rgba(205,63,69,.25)',    cursor:'#cfd2d1',  preview:['#151718','#cd3f45','#55b5db'] },
  { id:'ayu-dark',           label:'Ayu Dark',           dark:true,  bg:'#0d1017', gutter:'#0a0d13', text:'#bfbdb6', kw:'#f07178', type:'#39bae6', str:'#c2d94c', comment:'#626a73', num:'#e6b450', regex:'#95e6cb', arrow:'#f29668', ctx:'#59c2ff', interp:'#f29668', sel:'rgba(240,113,120,.2)',  cursor:'#e6b673',  preview:['#0d1017','#f07178','#c2d94c'] },
  { id:'ayu-mirage',         label:'Ayu Mirage',         dark:true,  bg:'#1f2430', gutter:'#191e28', text:'#cccac2', kw:'#f28779', type:'#5ccfe6', str:'#d5ff80', comment:'#5c6773', num:'#ffb454', regex:'#95e6cb', arrow:'#ffad66', ctx:'#73d0ff', interp:'#ffad66', sel:'rgba(242,135,121,.2)',  cursor:'#ffcc66',  preview:['#1f2430','#f28779','#d5ff80'] },
  { id:'railscasts',         label:'Railscasts',         dark:true,  bg:'#2b2b2b', gutter:'#242424', text:'#d5d5d5', kw:'#ff8c00', type:'#6d9cbe', str:'#a5c261', comment:'#bc9458', num:'#a5c261', regex:'#d3875c', arrow:'#9b703f', ctx:'#6d9cbe', interp:'#da4939', sel:'rgba(255,140,0,.2)',    cursor:'#d5d5d5',  preview:['#2b2b2b','#ff8c00','#a5c261'] },
  { id:'moonlight-pro',      label:'Moonlight Pro',      dark:true,  bg:'#222436', gutter:'#1b1d2d', text:'#c8d3f5', kw:'#fca7ea', type:'#4fd6be', str:'#c3e88d', comment:'#7a88cf', num:'#ff966c', regex:'#ff757f', arrow:'#89ddff', ctx:'#82aaff', interp:'#fca7ea', sel:'rgba(252,167,234,.15)', cursor:'#fca7ea',  preview:['#222436','#fca7ea','#c3e88d'] },
  { id:'spacegray',          label:'Spacegray',          dark:true,  bg:'#20242b', gutter:'#1a1e24', text:'#b3b8c3', kw:'#b0afc0', type:'#ac99d5', str:'#87c7a1', comment:'#444b55', num:'#ce7b3b', regex:'#ce5c5c', arrow:'#9b9dbd', ctx:'#8db9d7', interp:'#d19a66', sel:'rgba(176,175,192,.2)',  cursor:'#b3b8c3',  preview:['#20242b','#b0afc0','#87c7a1'] },
  { id:'miasma',             label:'Miasma',             dark:true,  bg:'#1a1a2e', gutter:'#16162a', text:'#e0d0c0', kw:'#c060a0', type:'#60c0c0', str:'#a0c060', comment:'#506070', num:'#e0a060', regex:'#e06060', arrow:'#c060a0', ctx:'#6080c0', interp:'#e08040', sel:'rgba(192,96,160,.2)',   cursor:'#c060a0',  preview:['#1a1a2e','#c060a0','#a0c060'] },
  { id:'solarized-light',    label:'Solarized Light',    dark:false, bg:'#fdf6e3', gutter:'#eee8d5', text:'#657b83', kw:'#859900', type:'#2aa198', str:'#2aa198', comment:'#93a1a1', num:'#d33682', regex:'#dc322f', arrow:'#268bd2', ctx:'#268bd2', interp:'#cb4b16', sel:'rgba(38,139,210,.15)',  cursor:'#657b83',  preview:['#fdf6e3','#859900','#2aa198'] },
  { id:'github-light',       label:'GitHub Light',       dark:false, bg:'#ffffff', gutter:'#f6f8fa', text:'#24292f', kw:'#d73a49', type:'#005cc5', str:'#032f62', comment:'#6a737d', num:'#005cc5', regex:'#032f62', arrow:'#6f42c1', ctx:'#e36209', interp:'#e36209', sel:'rgba(3,47,98,.1)',      cursor:'#24292f',  preview:['#ffffff','#d73a49','#032f62'] },
  { id:'one-light',          label:'One Light',          dark:false, bg:'#fafafa', gutter:'#f0f0f0', text:'#383a42', kw:'#a626a4', type:'#0184bb', str:'#50a14f', comment:'#a0a1a7', num:'#986801', regex:'#e45649', arrow:'#0184bb', ctx:'#4078f2', interp:'#c18401', sel:'rgba(64,120,242,.15)',  cursor:'#526fff',  preview:['#fafafa','#a626a4','#50a14f'] },
  { id:'catppuccin-latte',   label:'Catppuccin Latte',   dark:false, bg:'#eff1f5', gutter:'#e6e9f0', text:'#4c4f69', kw:'#8839ef', type:'#179299', str:'#40a02b', comment:'#8c8fa1', num:'#fe640b', regex:'#d20f39', arrow:'#1e66f5', ctx:'#04a5e5', interp:'#fe640b', sel:'rgba(136,57,239,.12)',  cursor:'#dc8a78',  preview:['#eff1f5','#8839ef','#40a02b'] },
  { id:'paperwhite',         label:'Paperwhite',         dark:false, bg:'#f5f0e8', gutter:'#ece7df', text:'#3c3c3c', kw:'#7b4d8a', type:'#2b6cb0', str:'#276749', comment:'#9d9d9d', num:'#c05621', regex:'#c53030', arrow:'#2b6cb0', ctx:'#2b6cb0', interp:'#c05621', sel:'rgba(123,77,138,.12)',  cursor:'#7b4d8a',  preview:['#f5f0e8','#7b4d8a','#276749'] },
  { id:'monochrome',         label:'Monochrome',         dark:true,  bg:'#111111', gutter:'#0d0d0d', text:'#cccccc', kw:'#ffffff', type:'#aaaaaa', str:'#888888', comment:'#444444', num:'#eeeeee', regex:'#ffffff', arrow:'#aaaaaa', ctx:'#cccccc', interp:'#ffffff', sel:'rgba(255,255,255,.12)',  cursor:'#ffffff',  preview:['#111111','#ffffff','#888888'] },
];

/* ── Current settings ────────────────────────────────────── */
const DS_KEY = 'vortex_dev_settings';

function _dsLoad() {
    try { return JSON.parse(localStorage.getItem(DS_KEY) || '{}'); } catch { return {}; }
}
function _dsSave(data) {
    const cur = _dsLoad();
    localStorage.setItem(DS_KEY, JSON.stringify(Object.assign(cur, data)));
}

/* ── Colour utils ────────────────────────────────────────── */
function _hexToRgb(hex) {
    hex = hex.replace('#', '');
    if (hex.length === 3) hex = hex.split('').map(c => c + c).join('');
    const n = parseInt(hex, 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
function _lighten(hex, amt) {
    const [r, g, b] = _hexToRgb(hex);
    const c = v => Math.max(0, Math.min(255, Math.round(v + amt)));
    return '#' + [c(r), c(g), c(b)].map(v => v.toString(16).padStart(2, '0')).join('');
}
function _rgba(hex, a) {
    const [r, g, b] = _hexToRgb(hex);
    return `rgba(${r},${g},${b},${a})`;
}

/* ── Apply theme ─────────────────────────────────────────── */
function _applyTheme(id) {
    const t = IDE_THEMES.find(t => t.id === id);
    if (!t) return;
    const root = document.documentElement;

    /* ─ Syntax colours ─ */
    root.style.setProperty('--gx-kw',      t.kw);
    root.style.setProperty('--gx-type',    t.type);
    root.style.setProperty('--gx-string',  t.str);
    root.style.setProperty('--gx-comment', t.comment);
    root.style.setProperty('--gx-num',     t.num);
    root.style.setProperty('--gx-regex',   t.regex);
    root.style.setProperty('--gx-arrow',   t.arrow);
    root.style.setProperty('--gx-ctx',     t.ctx);
    root.style.setProperty('--gx-interp',  t.interp);
    root.style.setProperty('--gx-command', t.kw);

    /* ─ Editor core ─ */
    root.style.setProperty('--ide-editor-bg', t.bg);
    root.style.setProperty('--ide-gutter-bg', t.gutter);
    root.style.setProperty('--ide-sel-bg',    t.sel);
    root.style.setProperty('--ide-text',      t.text);
    root.style.setProperty('--ide-cursor',    t.cursor);
    root.style.setProperty('--ide-accent',    t.cursor);

    /* ─ Compute surface colours from bg ─ */
    const shift = t.dark ? 1 : -1; // direction of offset (lighter vs darker)
    const surface1    = _lighten(t.bg, shift * 8);   // topbar
    const surface2    = _lighten(t.bg, shift * 5);   // sidebar
    const surface3    = _lighten(t.bg, -shift * 4);  // console (opposite direction)
    const simBg       = _lighten(t.bg, -shift * 6);  // simulator panel
    const borderAlpha = t.dark ? 0.55 : 0.3;
    const borderBase  = _lighten(t.bg, shift * 28);
    const border      = _rgba(borderBase, borderAlpha);
    const lineNumAlpha = t.dark ? 0.28 : 0.45;
    const lineNum     = _rgba(t.text, lineNumAlpha);
    const accentBg    = _rgba(t.cursor, t.dark ? 0.14 : 0.1);
    const userMsgBg   = _rgba(t.cursor, t.dark ? 0.2 : 0.12);

    const hoverBg = t.dark
        ? _rgba(_lighten(t.bg, 40), 0.09)
        : _rgba(_lighten(t.bg, -30), 0.08);

    root.style.setProperty('--ide-surface1',     surface1);
    root.style.setProperty('--ide-surface2',     surface2);
    root.style.setProperty('--ide-surface3',     surface3);
    root.style.setProperty('--ide-simulator-bg', simBg);
    root.style.setProperty('--ide-border',       border);
    root.style.setProperty('--ide-line-num',     lineNum);
    root.style.setProperty('--ide-accent-bg',    accentBg);
    root.style.setProperty('--ide-user-msg-bg',  userMsgBg);
    root.style.setProperty('--ide-hover-bg',     hoverBg);

    /* ─ mark selected card ─ */
    document.querySelectorAll('.dev-theme-card').forEach(c => {
        c.classList.toggle('active', c.dataset.themeId === id);
    });
    _dsSave({ theme: id });
}

/* ── Apply editor font settings ──────────────────────────── */
function _applyEditorFont(family, size, lineHeight) {
    const root = document.documentElement;
    if (family)     root.style.setProperty('--ide-font-family', family);
    if (size)       root.style.setProperty('--ide-font-size', size + 'px');
    if (lineHeight) root.style.setProperty('--ide-line-height', lineHeight);
}

/* ── Apply feature flags ─────────────────────────────────── */
function _applyFeature(key, val) {
    document.documentElement.classList.toggle('ide-feat-' + key, !!val);
    _dsSave({ ['feat_' + key]: val });
    if (key === 'typing-sound') {
        val ? _initTypingSound() : _stopTypingSound();
    }
    if (key === 'code-rain') {
        val ? _initCodeRain() : _stopCodeRain();
    }
    if (key === 'zen-mode' && val) {
        _activateZenMode();
    }
}

/* ── Typing sound engine ─────────────────────────────────── */
let _audioCtx = null;
function _initTypingSound() {
    document.addEventListener('keydown', _onTypingKey);
}
function _stopTypingSound() {
    document.removeEventListener('keydown', _onTypingKey);
}
function _onTypingKey(e) {
    const ide = document.getElementById('tab-view-ide');
    if (!ide || ide.style.display === 'none') return;
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (!_audioCtx) _audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const ctx = _audioCtx;
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    o.connect(g); g.connect(ctx.destination);
    const freq = 800 + Math.random() * 400;
    o.frequency.setValueAtTime(freq, ctx.currentTime);
    o.frequency.exponentialRampToValueAtTime(freq * 0.5, ctx.currentTime + 0.04);
    o.type = 'sawtooth';
    g.gain.setValueAtTime(0.06, ctx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.06);
    o.start(ctx.currentTime);
    o.stop(ctx.currentTime + 0.06);
}

/* ── Code rain (idle matrix) ─────────────────────────────── */
let _rainCanvas = null, _rainAnim = null, _rainTimer = null;
const _RAIN_IDLE_DELAY = 45000; // 45s idle
function _initCodeRain() {
    document.addEventListener('mousemove', _resetRainTimer);
    document.addEventListener('keydown', _resetRainTimer);
    _resetRainTimer();
}
function _stopCodeRain() {
    document.removeEventListener('mousemove', _resetRainTimer);
    document.removeEventListener('keydown', _resetRainTimer);
    clearTimeout(_rainTimer);
    _hideRain();
}
function _resetRainTimer() {
    clearTimeout(_rainTimer);
    _hideRain();
    _rainTimer = setTimeout(_showRain, _RAIN_IDLE_DELAY);
}
function _showRain() {
    const ide = document.getElementById('tab-view-ide');
    if (!ide || ide.style.display === 'none') return;
    if (_rainCanvas) return;
    const c = document.createElement('canvas');
    c.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:9998;pointer-events:none;opacity:0;transition:opacity 1s';
    document.body.appendChild(c);
    _rainCanvas = c;
    c.width = window.innerWidth; c.height = window.innerHeight;
    const ctx = c.getContext('2d');
    const cols = Math.floor(c.width / 14);
    const drops = Array(cols).fill(0).map(() => Math.random() * -50 | 0);
    const CHARS = '0123456789ABCDEF{}[]()<>=!&|^~;:.,/\\+-*%$@#`?_\'"';
    let frame = 0;
    function draw() {
        ctx.fillStyle = 'rgba(0,0,0,0.05)';
        ctx.fillRect(0, 0, c.width, c.height);
        const themeColor = getComputedStyle(document.documentElement).getPropertyValue('--gx-kw').trim() || '#00ff41';
        ctx.fillStyle = themeColor;
        ctx.font = '13px monospace';
        for (let i = 0; i < cols; i++) {
            const ch = CHARS[Math.random() * CHARS.length | 0];
            ctx.fillStyle = i % 3 === 0 ? '#ffffff' : themeColor;
            ctx.fillText(ch, i * 14, drops[i] * 14);
            if (drops[i] * 14 > c.height && Math.random() > 0.975) drops[i] = 0;
            drops[i]++;
        }
        frame++;
        _rainAnim = requestAnimationFrame(draw);
    }
    requestAnimationFrame(() => { c.style.opacity = '0.6'; });
    draw();
    // click anywhere to dismiss
    c.style.pointerEvents = 'auto';
    c.addEventListener('click', _hideRain, { once: true });
}
function _hideRain() {
    if (!_rainCanvas) return;
    cancelAnimationFrame(_rainAnim);
    _rainCanvas.style.opacity = '0';
    setTimeout(() => { _rainCanvas && _rainCanvas.remove(); _rainCanvas = null; }, 1000);
}

/* ── Zen mode ────────────────────────────────────────────── */
function _activateZenMode() {
    const ide = document.getElementById('tab-view-ide');
    if (!ide) return;
    ide.classList.add('ide-zen-mode');
    const btn = document.createElement('button');
    btn.className = 'ide-zen-exit';
    btn.textContent = 'Esc';
    btn.title = window.t ? window.t('ide.exitZenMode') : 'Exit Zen Mode';
    btn.onclick = () => { ide.classList.remove('ide-zen-mode'); btn.remove(); };
    ide.appendChild(btn);
    document.addEventListener('keydown', function esc(e) {
        if (e.key === 'Escape') { ide.classList.remove('ide-zen-mode'); btn.remove(); document.removeEventListener('keydown', esc); }
    });
}

/* ── Background image ────────────────────────────────────── */
function _applyCodeBg(dataUrl, blur, opacity) {
    const root = document.documentElement;
    if (dataUrl) {
        root.style.setProperty('--ide-bg-image', `url("${dataUrl}")`);
        _dsSave({ codeBg: dataUrl, codeBgBlur: blur ?? 4, codeBgOpacity: opacity ?? 0.12 });
    }
    const b = blur  ?? +(_dsLoad().codeBgBlur ?? 4);
    const o = opacity ?? +(_dsLoad().codeBgOpacity ?? 0.12);
    root.style.setProperty('--ide-bg-blur',    b + 'px');
    root.style.setProperty('--ide-bg-opacity', o);
}

function _clearCodeBg() {
    document.documentElement.style.removeProperty('--ide-bg-image');
    const ds = _dsLoad();
    delete ds.codeBg;
    localStorage.setItem(DS_KEY, JSON.stringify(ds));
    const prev = document.getElementById('dev-bg-preview');
    if (prev) { prev.style.backgroundImage = ''; prev.textContent = (window.t ? '📂 ' + window.t('ide.noBackground') : '📂 No background'); }
    document.getElementById('dev-bg-clear') && (document.getElementById('dev-bg-clear').style.display = 'none');
}

/* ── Pomodoro timer ──────────────────────────────────────── */
let _pom = null;
function _togglePomodoro() {
    if (_pom) { _stopPomodoro(); return; }
    _startPomodoro(25);
}
function _startPomodoro(minutes) {
    let secs = minutes * 60;
    let overlay = document.getElementById('ide-pom-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'ide-pom-overlay';
        overlay.className = 'ide-pom-overlay';
        overlay.innerHTML = `
          <div class="ide-pom-ring">
            <svg viewBox="0 0 60 60"><circle cx="30" cy="30" r="26" class="pom-track"/><circle cx="30" cy="30" r="26" class="pom-prog" id="pom-arc"/></svg>
            <span id="pom-time"></span>
          </div>
          <div class="ide-pom-controls">
            <button onclick="window.DevSettings.stopPomodoro()" title="Stop">✕</button>
          </div>`;
        document.body.appendChild(overlay);
    }
    const arc = document.getElementById('pom-arc');
    const timeEl = document.getElementById('pom-time');
    const total = secs;
    const CIRCUM = 2 * Math.PI * 26;
    arc.style.strokeDasharray = CIRCUM;
    function tick() {
        if (secs < 0) { _stopPomodoro(); _showPomDone(); return; }
        const m = (secs / 60 | 0), s = secs % 60;
        timeEl.textContent = `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
        arc.style.strokeDashoffset = CIRCUM * (1 - secs / total);
        secs--;
        _pom = setTimeout(tick, 1000);
    }
    tick();
}
function _stopPomodoro() {
    clearTimeout(_pom); _pom = null;
    const overlay = document.getElementById('ide-pom-overlay');
    if (overlay) overlay.remove();
}
function _showPomDone() {
    const n = document.createElement('div');
    n.className = 'ide-pom-done';
    n.textContent = '🍅 ' + (window.t ? window.t('ide.breakTime') : 'Break time! Take 5 minutes.');
    document.body.appendChild(n);
    setTimeout(() => n.remove(), 5000);
}

/* ── Boot: restore settings ──────────────────────────────── */
function _bootRestore() {
    const ds = _dsLoad();
    if (ds.theme) _applyTheme(ds.theme);
    if (ds.fontFamily || ds.fontSize || ds.lineHeight) {
        _applyEditorFont(ds.fontFamily, ds.fontSize, ds.lineHeight);
    }
    if (ds.codeBg) _applyCodeBg(ds.codeBg, ds.codeBgBlur, ds.codeBgOpacity);
    // features
    const feats = ['typing-sound','code-rain','bracket-rainbow','error-lens','word-highlight','minimap','cursor-glow','smooth-caret','heatmap'];
    feats.forEach(f => { if (ds['feat_' + f]) _applyFeature(f, true); });
    if (ds.tabSize) document.documentElement.style.setProperty('--ide-tab-size', ds.tabSize);
}

/* ── Render dev settings section ─────────────────────────── */
function renderDevSettings() {
    const ds = _dsLoad();
    const curTheme = ds.theme || 'vortex-night';
    const section = document.getElementById('settings-dev');
    if (!section) return;

    /* Theme grid */
    const themeGrid = section.querySelector('#dev-theme-grid');
    if (themeGrid && !themeGrid.dataset.built) {
        themeGrid.dataset.built = '1';
        IDE_THEMES.forEach(t => {
            const card = document.createElement('button');
            card.className = 'dev-theme-card' + (t.id === curTheme ? ' active' : '');
            card.dataset.themeId = t.id;
            card.title = t.label;
            card.innerHTML = `
              <div class="dev-theme-swatch">
                <div style="background:${t.preview[0]};flex:1;border-radius:4px 4px 0 0;display:flex;align-items:center;padding:4px 5px;gap:3px;flex-wrap:wrap;">
                  <span style="width:8px;height:8px;border-radius:2px;background:${t.preview[1]};flex-shrink:0;"></span>
                  <span style="width:6px;height:8px;border-radius:2px;background:${t.preview[2]};flex-shrink:0;"></span>
                  <span style="width:10px;height:8px;border-radius:2px;background:${t.text};opacity:.4;flex-shrink:0;"></span>
                </div>
              </div>
              <div class="dev-theme-label">${t.label}</div>`;
            card.addEventListener('click', () => _applyTheme(t.id));
            themeGrid.appendChild(card);
        });
    }

    /* Font family select */
    const fontSel = section.querySelector('#dev-font-family');
    if (fontSel && ds.fontFamily) fontSel.value = ds.fontFamily;

    /* Font size */
    const fontSzEl = section.querySelector('#dev-font-size');
    if (fontSzEl) fontSzEl.value = ds.fontSize || 13;

    /* Line height */
    const lhEl = section.querySelector('#dev-line-height');
    if (lhEl) lhEl.value = ds.lineHeight || 1.65;

    /* Tab size */
    const tabEl = section.querySelector('#dev-tab-size');
    if (tabEl) tabEl.value = ds.tabSize || 4;

    /* BG preview */
    const bgPrev = section.querySelector('#dev-bg-preview');
    if (bgPrev && ds.codeBg) {
        bgPrev.style.backgroundImage = `url("${ds.codeBg}")`;
        bgPrev.textContent = '';
        const clr = section.querySelector('#dev-bg-clear');
        if (clr) clr.style.display = '';
    }

    /* Blur / opacity sliders */
    const blurEl = section.querySelector('#dev-bg-blur');
    if (blurEl) blurEl.value = ds.codeBgBlur ?? 4;
    const opEl = section.querySelector('#dev-bg-opacity');
    if (opEl) opEl.value = Math.round((ds.codeBgOpacity ?? 0.12) * 100);

    /* Feature toggles */
    const feats = ['typing-sound','code-rain','bracket-rainbow','error-lens','word-highlight','minimap','cursor-glow','smooth-caret','heatmap'];
    feats.forEach(f => {
        const el = section.querySelector(`#dev-feat-${f}`);
        if (el) el.checked = !!ds['feat_' + f];
    });
}

/* ── Public API ──────────────────────────────────────────── */
window.DevSettings = {
    themes: IDE_THEMES,
    applyTheme: _applyTheme,
    applyEditorFont: _applyEditorFont,
    applyFeature: _applyFeature,
    applyCodeBg: _applyCodeBg,
    clearCodeBg: _clearCodeBg,
    togglePomodoro: _togglePomodoro,
    stopPomodoro: _stopPomodoro,
    renderDevSettings,
    handleBgUpload(e) {
        const file = e.target.files[0];
        if (!file) return;
        if (!file.type.startsWith('image/')) return;
        const reader = new FileReader();
        reader.onload = ev => {
            _applyCodeBg(ev.target.result);
            const section = document.getElementById('settings-dev');
            if (section) {
                const bgPrev = section.querySelector('#dev-bg-preview');
                if (bgPrev) { bgPrev.style.backgroundImage = `url("${ev.target.result}")`; bgPrev.textContent = ''; }
                const clr = section.querySelector('#dev-bg-clear');
                if (clr) clr.style.display = '';
            }
        };
        reader.readAsDataURL(file);
    },
    onFontChange() {
        const section = document.getElementById('settings-dev');
        if (!section) return;
        const family = section.querySelector('#dev-font-family')?.value;
        const size   = +section.querySelector('#dev-font-size')?.value || 13;
        const lh     = +section.querySelector('#dev-line-height')?.value || 1.65;
        _applyEditorFont(family, size, lh);
        _dsSave({ fontFamily: family, fontSize: size, lineHeight: lh });
    },
    onTabSizeChange() {
        const val = document.getElementById('dev-tab-size')?.value || 4;
        document.documentElement.style.setProperty('--ide-tab-size', val);
        _dsSave({ tabSize: +val });
    },
    onBlurChange() {
        const blur = +document.getElementById('dev-bg-blur')?.value;
        document.documentElement.style.setProperty('--ide-bg-blur', blur + 'px');
        _dsSave({ codeBgBlur: blur });
    },
    onOpacityChange() {
        const pct = +document.getElementById('dev-bg-opacity')?.value;
        const op = pct / 100;
        document.documentElement.style.setProperty('--ide-bg-opacity', op);
        _dsSave({ codeBgOpacity: op });
    },
};

/* boot */
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _bootRestore);
} else {
    _bootRestore();
}

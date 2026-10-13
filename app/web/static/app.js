// Tabs
document.querySelectorAll('[role=tab]').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('[role=tab]').forEach(t =>
      t.setAttribute('aria-selected', t === tab ? 'true' : 'false'));
    document.querySelectorAll('.panel').forEach(p =>
      p.hidden = p.id !== 'tab-' + tab.dataset.tab);
  });
});

// Download the JSON report
const dl = document.getElementById('download');
if (dl) {
  dl.addEventListener('click', () => {
    const data = JSON.stringify(
      JSON.parse(document.getElementById('report-data').textContent), null, 2);
    const url = URL.createObjectURL(new Blob([data], { type: 'application/json' }));
    const a = Object.assign(document.createElement('a'),
      { href: url, download: dl.dataset.filename || 'report.json' });
    a.click();
    URL.revokeObjectURL(url);
  });
}

// Upload page: show file name, drag and drop, busy state
const form = document.getElementById('scan-form');
if (form) {
  const input = document.getElementById('file');
  const drop = form.querySelector('.drop');
  const text = document.getElementById('drop-text');
  const btn = document.getElementById('scan-btn');

  input.addEventListener('change', () => {
    if (input.files[0]) text.textContent = input.files[0].name;
  });
  ['dragover', 'dragenter'].forEach(e => drop.addEventListener(e, ev => {
    ev.preventDefault(); drop.classList.add('over');
  }));
  ['dragleave', 'drop'].forEach(e => drop.addEventListener(e, () => drop.classList.remove('over')));
  drop.addEventListener('drop', ev => {
    ev.preventDefault();
    input.files = ev.dataTransfer.files;
    input.dispatchEvent(new Event('change'));
  });
    form.addEventListener('submit', () => { btn.disabled = true; btn.textContent = 'Scanning...'; });
}
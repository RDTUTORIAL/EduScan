export const exportToJson = (payload, filename = 'eduscan-export.json') => {
  const data = typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
};
